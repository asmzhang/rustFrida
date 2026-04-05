use crate::net::communication::{log_msg, send_complete, send_eval_err, send_eval_ok, write_stream};
use crate::SHOULD_EXIT;
use std::sync::atomic::Ordering;

/// 执行 JS 脚本并通过 EVAL:/EVAL_ERR: 协议返回结果。
/// 此方法属于异步双向交互响应层。
#[cfg(feature = "quickjs")]
pub fn eval_and_respond(script: &str, empty_err: &[u8]) {
    if script.is_empty() {
        send_eval_err(std::str::from_utf8(empty_err).unwrap_or("[quickjs] empty script"));
    } else if !crate::features::quickjs_loader::is_initialized() {
        send_eval_err("[quickjs] JS 引擎未初始化，请先执行 jsinit");
    } else {
        match crate::features::quickjs_loader::execute_script(script) {
            Ok(result) => send_eval_ok(&result),
            Err(e) => {
                let e = e.replace('\n', "\r");
                send_eval_err(&e);
            }
        }
    }
}

/// 全局系统指令分发器 (Dispatcher)
/// 负责将传入的字符串命令解析并路由给具体的执行模块引擎。
/// 未来可进一步演进成 HashMap 或命令枚举匹配。
pub fn dispatch(command: &str) {
    // 取出首个词组作为命令指令
    match command.split_whitespace().next() {
        Some("trace") => {
            let tid = command
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            std::thread::spawn(move || {
                match crate::engine::trace::gum_modify_thread(tid) {
                    Ok(pid) => {
                        write_stream(format!("clone success {}", pid).as_bytes());
                    }
                    Err(e) => {
                        write_stream(format!("error: {}", e).as_bytes());
                    }
                }
                unsafe { libc::kill(std::process::id() as libc::pid_t, libc::SIGSTOP) }
            });
        }
        #[cfg(feature = "frida-gum")]
        Some("stalker") => {
            let tid = command
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            crate::engine::stalker::follow(tid)
        }
        #[cfg(feature = "frida-gum")]
        Some("hfl") => {
            let mut cmds = command.split_whitespace();
            let md = cmds.nth(1).unwrap();
            let offset = cmds
                .next()
                .and_then(|s| {
                    let s = s.strip_prefix("0x").unwrap_or(s);
                    usize::from_str_radix(s, 16).ok()
                })
                .unwrap_or(0);
            crate::engine::stalker::hfollow(md, offset)
        }
        #[cfg(feature = "quickjs")]
        Some("__set_verbose__") => {
            quickjs_hook::set_verbose(true);
        }
        #[cfg(feature = "quickjs")]
        Some("artinit") => {
            // 预初始化 artController Layer 1+2 (spawn 模式, 进程暂停时调用)
            match quickjs_hook::jsapi::java::pre_init_art_controller() {
                Ok(_) => send_eval_ok("artinit_ok"),
                Err(e) => send_eval_err(&format!("artinit failed: {}", e)),
            }
        }
        #[cfg(feature = "quickjs")]
        Some("jsinit") => match crate::features::quickjs_loader::init() {
            Ok(_) => send_eval_ok("initialized"),
            Err(e) => send_eval_err(&e),
        },
        // javainit: 延迟 JNI 初始化（spawn 模式 resume 后调用）
        // AttachCurrentThread + cache reflect IDs
        #[cfg(feature = "quickjs")]
        Some("javainit") => match quickjs_hook::deferred_java_init() {
            Ok(_) => send_eval_ok("java_initialized"),
            Err(e) => send_eval_err(&e),
        },
        #[cfg(feature = "quickjs")]
        Some("loadjs") => {
            let script = command.strip_prefix("loadjs").unwrap_or("").trim();
            eval_and_respond(script, b"EVAL_ERR:[quickjs] Error: empty script\n");
        }
        #[cfg(feature = "quickjs")]
        Some("jseval") => {
            let expr = command.strip_prefix("jseval").unwrap_or("").trim();
            eval_and_respond(expr, "EVAL_ERR:[quickjs] 用法: jseval <expression>\n".as_bytes());
        }
        #[cfg(feature = "quickjs")]
        Some("jscomplete") => {
            let prefix = command.strip_prefix("jscomplete").unwrap_or("").trim();
            let result = crate::features::quickjs_loader::complete(prefix);
            send_complete(&result);
        }
        #[cfg(feature = "quickjs")]
        Some("jsclean") => {
            if !crate::features::quickjs_loader::is_initialized() {
                send_eval_err("[quickjs] JS 引擎未初始化");
            } else {
                crate::features::quickjs_loader::cleanup();
                send_eval_ok("cleaned up");
            }
        }
        Some("recomp") => {
            let addr_str = command.split_whitespace().nth(1).unwrap_or("");
            let addr_str = addr_str.strip_prefix("0x").unwrap_or(addr_str);
            match usize::from_str_radix(addr_str, 16) {
                Ok(addr) => match crate::engine::recompiler::recompile(addr, 0) {
                    Ok((recomp_base, stats)) => {
                        send_eval_ok(&format!(
                            "recomp 0x{:x} → 0x{:x} (copied={} intra={} reloc={} tramp={})",
                            addr,
                            recomp_base,
                            stats.num_copied,
                            stats.num_intra_page,
                            stats.num_direct_reloc,
                            stats.num_trampolines
                        ));
                    }
                    Err(e) => send_eval_err(&e),
                },
                Err(_) => send_eval_err("用法: recomp 0x<page_addr>"),
            }
        }
        Some("recomp-release") => {
            let addr_str = command.split_whitespace().nth(1).unwrap_or("");
            let addr_str = addr_str.strip_prefix("0x").unwrap_or(addr_str);
            match usize::from_str_radix(addr_str, 16) {
                Ok(addr) => match crate::engine::recompiler::release(addr, 0) {
                    Ok(_) => send_eval_ok("released"),
                    Err(e) => send_eval_err(&e),
                },
                Err(_) => send_eval_err("用法: recomp-release 0x<page_addr>"),
            }
        }
        Some("recomp-dry") => {
            let addr_str = command.split_whitespace().nth(1).unwrap_or("");
            let addr_str = addr_str.strip_prefix("0x").unwrap_or(addr_str);
            match usize::from_str_radix(addr_str, 16) {
                Ok(addr) => match crate::engine::recompiler::dry_run(addr) {
                    Ok(output) => send_eval_ok(&output),
                    Err(e) => send_eval_err(&e),
                },
                Err(_) => send_eval_err("用法: recomp-dry 0x<addr>"),
            }
        }
        Some("recomp-list") => {
            let pages = crate::engine::recompiler::list_pages();
            if pages.is_empty() {
                send_eval_ok("无重编译页");
            } else {
                let mut msg = String::new();
                for (orig, recomp, tramp) in &pages {
                    msg.push_str(&format!("0x{:x} → 0x{:x} (tramp={})\n", orig, recomp, tramp));
                }
                send_eval_ok(&msg);
            }
        }
        // shutdown — 先完整清理并输出日志，最后由 agent 主动关闭 socket
        Some("shutdown") => {
            log_msg("收到 shutdown，开始退出清理\n".to_string());
            #[cfg(feature = "quickjs")]
            if crate::features::quickjs_loader::is_initialized() {
                crate::features::quickjs_loader::cleanup();
            }
            // 关键: 在 agent SO 被 dlclose 之前恢复旧信号处理器，
            // 否则 sigaction 表中的 handler 指针指向已卸载的内存，
            // 进程触发任何信号(如 ART 隐式 null check)即崩溃
            crate::sys::crash_handler::uninstall_crash_handlers();
            log_msg("退出清理完成，准备关闭 socket\n".to_string());
            SHOULD_EXIT.store(true, Ordering::Relaxed);
        }
        _ => {
            let cmd_name = command.split_whitespace().next().unwrap_or("(empty)");
            log_msg(format!("无效命令 '{}'，在 REPL 中输入 help 查看可用命令\n", cmd_name));
        }
    }
}
