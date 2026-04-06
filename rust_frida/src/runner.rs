#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use crate::args::Args;
#[cfg(feature = "qbdi")]
use crate::communication::send_qbdi_helper;
use crate::communication::{send_command, start_socketpair_handler};
use crate::injection::{inject_via_bootstrapper, watch_and_inject};
use crate::process::find_pid_by_name;
use crate::repl::{print_eval_result, run_main_repl};
use crate::session::Session;
use crate::spawn;
use crate::types::get_string_table_names;
#[allow(unused_imports)]
use crate::{log_error, log_info, log_success, log_warn};

use std::os::unix::io::RawFd;
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub(crate) fn start_interactive_session(args: &Args) {
    // 解析 --name 到 PID（如果指定）
    let resolved_pid: Option<i32> = if let Some(ref name) = args.name {
        match find_pid_by_name(name) {
            Ok(pid) => {
                log_success!("按名称 '{}' 找到进程 PID: {}", name, pid);
                Some(pid)
            }
            Err(e) => {
                log_error!("{}", e);
                std::process::exit(1);
            }
        }
    } else {
        args.pid
    };

    // 解析字符串覆盖参数（格式：name=value）
    let mut string_overrides = std::collections::HashMap::new();
    let available_names = get_string_table_names();

    for s in &args.strings {
        if let Some((name, value)) = s.split_once('=') {
            if available_names.contains(&name) {
                string_overrides.insert(name.to_string(), value.to_string());
            } else {
                log_warn!("未知的字符串名称 '{}', 可用名称: {}", name, available_names.join(", "));
            }
        } else {
            log_warn!("无效的字符串格式 '{}', 应为 name=value", s);
        }
    }

    if !string_overrides.is_empty() {
        log_info!("字符串覆盖列表 ({} 个):", string_overrides.len());
        for (name, value) in &string_overrides {
            println!("     {} = {}", name, value);
        }
    }

    // 根据参数选择注入方式，返回 (target_pid, host_fd)
    let (target_pid, host_fd): (Option<i32>, RawFd) = if let Some(ref package) = args.spawn {
        spawn::register_cleanup_handler();
        match spawn::spawn_and_inject(package, &string_overrides) {
            Ok((pid, fd)) => (Some(pid), fd),
            Err(e) => {
                log_error!("Spawn 注入失败: {}", e);
                spawn::cleanup_zygote_patches();
                std::process::exit(1);
            }
        }
    } else if let Some(so_pattern) = &args.watch_so {
        match watch_and_inject(so_pattern, args.timeout, &string_overrides) {
            Ok(fd) => (resolved_pid, fd),
            Err(e) => {
                log_error!("注入失败: {}", e);
                std::process::exit(1);
            }
        }
    } else if let Some(pid) = resolved_pid {
        match inject_via_bootstrapper(pid, &string_overrides) {
            Ok(fd) => (Some(pid), fd),
            Err(e) => {
                log_error!("注入失败: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        log_error!("必须指定 --pid、--name、--watch-so、--spawn 或 --server");
        std::process::exit(1);
    };

    let label = if let Some(ref pkg) = args.spawn {
        pkg.clone()
    } else if let Some(ref name) = args.name {
        name.clone()
    } else if let Some(pid) = target_pid {
        format!("PID:{}", pid)
    } else {
        "unknown".to_string()
    };

    let session = Arc::new(Session::new(0, label));
    if let Some(pid) = target_pid {
        session.pid.store(pid, Ordering::Relaxed);
    }

    let _handle = start_socketpair_handler(host_fd, session.clone());

    {
        log_info!("等待 agent 连接... (最长 {}s)", args.connect_timeout);
        let connected = if args.spawn.is_some() {
            session.wait_connected_with_signal(args.connect_timeout, || spawn::signal_received())
        } else {
            session.wait_connected(args.connect_timeout)
        };

        if args.spawn.is_some() && spawn::signal_received() {
            log_info!("收到终止信号，正在清理...");
            spawn::cleanup_zygote_patches();
            std::process::exit(1);
        }

        if !connected {
            log_error!("等待 agent 连接超时 ({}s)，请检查:", args.connect_timeout);
            if let Some(pid) = target_pid {
                if std::path::Path::new(&format!("/proc/{}/status", pid)).exists() {
                    log_warn!("  目标进程 {} 仍在运行（agent 可能崩溃或未加载）", pid);
                } else {
                    log_warn!("  目标进程 {} 已退出（可能被 OOM 或信号终止）", pid);
                }
            }
            log_warn!("  1. dmesg | grep -i 'deny\\|avc'  （SELinux 拦截？）");
            log_warn!("  2. logcat | grep -E 'FATAL|crash'  （agent 崩溃？）");
            log_warn!("  3. 使用 --verbose 重新运行查看详细注入日志");
            log_warn!("  4. adb logcat | grep rustFrida  （查看 agent 日志）");
            if let Some(pid) = target_pid {
                if args.spawn.is_some() {
                    let _ = spawn::resume_child(pid as u32);
                }
            }
            std::process::exit(1);
        }
    }
    let sender = session.get_sender().unwrap();

    if args.verbose {
        let _ = send_command(sender, "__set_verbose__");
    }

    #[cfg(feature = "qbdi")]
    {
        if let Err(e) = send_qbdi_helper(sender, crate::injection::QBDI_HELPER_SO.to_vec()) {
            log_error!("发送 QBDI helper 失败: {}", e);
            std::process::exit(1);
        }
    }

    if let Some(ref _package) = args.spawn {
        if let Some(pid) = target_pid {
            if spawn::signal_received() {
                log_info!("收到终止信号，正在清理...");
                spawn::cleanup_zygote_patches();
                std::process::exit(1);
            }
            if let Some(script_path) = &args.load_script {
                match std::fs::read_to_string(script_path) {
                    Ok(script) => {
                        log_info!("加载脚本 (子进程暂停中): {}", script_path);
                        session.eval_state.clear();
                        if let Err(e) = send_command(sender, "jsinit") {
                            log_error!("发送 jsinit 失败: {}", e);
                        } else {
                            match session.eval_state.recv_timeout(std::time::Duration::from_secs(10)) {
                                None => log_warn!("等待引擎初始化超时"),
                                Some(Err(e)) => log_error!("引擎初始化失败: {}", e),
                                Some(Ok(_)) => {
                                    let script_line = script.replace('\n', "\r");
                                    session.eval_state.clear();
                                    let cmd = format!("loadjs {}", script_line);
                                    if let Err(e) = send_command(sender, cmd) {
                                        log_error!("发送 loadjs 失败: {}", e);
                                    } else {
                                        print_eval_result(&session, 30);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log_error!("读取脚本文件 '{}' 失败: {}", script_path, e);
                    }
                }
            }
            if let Err(e) = spawn::resume_child(pid as u32) {
                log_error!("恢复子进程失败: {}", e);
            }
        }
    }

    if args.spawn.is_none() {
        if let Some(script_path) = &args.load_script {
            match std::fs::read_to_string(script_path) {
                Ok(script) => {
                    log_info!("加载脚本: {}", script_path);
                    session.eval_state.clear();
                    if let Err(e) = send_command(sender, "jsinit") {
                        log_error!("发送 jsinit 失败: {}", e);
                    } else {
                        match session.eval_state.recv_timeout(std::time::Duration::from_secs(10)) {
                            None => log_warn!("等待引擎初始化超时"),
                            Some(Err(e)) => log_error!("引擎初始化失败: {}", e),
                            Some(Ok(_)) => {
                                let script_line = script.replace('\n', "\r");
                                session.eval_state.clear();
                                let cmd = format!("loadjs {}", script_line);
                                if let Err(e) = send_command(sender, cmd) {
                                    log_error!("发送 loadjs 失败: {}", e);
                                } else {
                                    print_eval_result(&session, 30);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    log_error!("读取脚本文件 '{}' 失败: {}", script_path, e);
                }
            }
        }
    }

    // 转移控制权给 REPL 循环
    run_main_repl(&session, args);
}
