//! ldmonitor - KPM-based library loading monitor
//!
//! This library provides functionality to monitor `android_dlopen_ext` calls
//! using KPM (Kernel Profiling Module) dmesg streams.

use log::debug;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use tokio::runtime::Runtime;

pub use ldmonitor_common::{DlopenEvent, MAX_PATH_LEN};

/// 从 /proc/<pid>/status 读取 NSpid 字段，返回各namespace层级的PID列表
///
/// NSpid 格式: NSpid: <root_ns_pid> <ns1_pid> <ns2_pid> ...
/// 从外层(root)到内层排列，最后一个是进程所在最内层namespace的PID
fn get_nspid(host_pid: u32) -> Option<Vec<u32>> {
    let status_path = format!("/proc/{}/status", host_pid);
    let content = fs::read_to_string(&status_path).ok()?;

    for line in content.lines() {
        if line.starts_with("NSpid:") {
            let pids: Vec<u32> = line
                .trim_start_matches("NSpid:")
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            if !pids.is_empty() {
                return Some(pids);
            }
        }
    }
    None
}

/// 获取当前进程的 PID namespace inode
fn get_current_pid_ns() -> Option<u64> {
    let link = fs::read_link("/proc/self/ns/pid").ok()?;
    // 格式: pid:[4026531836]
    let s = link.to_string_lossy();
    let start = s.find('[')? + 1;
    let end = s.find(']')?;
    s[start..end].parse().ok()
}

/// 获取指定进程的 PID namespace inode
fn get_pid_ns(pid: u32) -> Option<u64> {
    let link = fs::read_link(format!("/proc/{}/ns/pid", pid)).ok()?;
    let s = link.to_string_lossy();
    let start = s.find('[')? + 1;
    let end = s.find(']')?;
    s[start..end].parse().ok()
}

/// 将 host PID 转换为当前 namespace 的 PID
///
/// 如果进程在同一namespace或嵌套namespace中，返回对应的namespace PID
/// 如果无法转换（不同namespace分支），返回 None
pub fn translate_pid_to_current_ns(host_pid: u32) -> Option<u32> {
    let nspids = get_nspid(host_pid)?;

    // 如果只有一个PID，说明进程在root namespace
    if nspids.len() == 1 {
        return Some(nspids[0]);
    }

    // 获取当前namespace和目标进程namespace
    let current_ns = get_current_pid_ns()?;
    let target_ns = get_pid_ns(host_pid)?;

    // 如果在同一namespace，返回最内层的PID
    if current_ns == target_ns {
        return nspids.last().copied();
    }

    // 尝试返回最内层namespace的PID（适用于嵌套容器场景）
    // 这是最常见的场景：监控程序和目标进程在同一个容器内
    nspids.last().copied()
}

/// 监听到的 dlopen 事件
#[derive(Debug, Clone)]
pub struct DlopenInfo {
    /// 宿主机 namespace 的 PID
    pub host_pid: u32,
    /// 当前 namespace 的 PID（如果能转换的话）
    pub ns_pid: Option<u32>,
    pub uid: u32,
    pub path: String,
}

impl DlopenInfo {
    /// 获取可用的 PID（优先返回 namespace PID）
    pub fn pid(&self) -> u32 {
        self.ns_pid.unwrap_or(self.host_pid)
    }
}

impl From<&DlopenEvent> for DlopenInfo {
    fn from(event: &DlopenEvent) -> Self {
        let host_pid = event.pid;
        let ns_pid = translate_pid_to_current_ns(host_pid);

        Self {
            host_pid,
            ns_pid,
            uid: event.uid,
            path: event.path_str().to_string(),
        }
    }
}

/// KPM dlopen 监听器
pub struct DlopenMonitor {
    receiver: Receiver<DlopenInfo>,
    stop_flag: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl DlopenMonitor {
    /// 创建新的监听器
    ///
    /// # Arguments
    /// * `target_pid` - 可选的目标进程 PID，如果为 None 则监听所有进程
    pub fn new(target_pid: Option<u32>) -> anyhow::Result<Self> {
        // 设置 memlock 限制
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {ret}");
        }

        let (sender, receiver) = mpsc::channel();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();

        let handle = thread::spawn(move || {
            let rt = Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(async move {
                if let Err(e) = run_monitor(target_pid, sender, stop_flag_clone).await {
                    eprintln!("Monitor error: {}", e);
                }
            });
        });

        Ok(Self {
            receiver,
            stop_flag,
            handle: Some(handle),
        })
    }

    /// 停止监听
    pub fn stop(self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        // if let Some(handle) = self.handle.take() {
        //     let _ = handle.join();
        // }
        println!("KPM 监听已停止");
    }

    /// 阻塞等待下一个 dlopen 事件
    pub fn recv(&self) -> Option<DlopenInfo> {
        self.receiver.recv().ok()
    }

    /// 非阻塞尝试接收 dlopen 事件
    pub fn try_recv(&self) -> Option<DlopenInfo> {
        self.receiver.try_recv().ok()
    }

    /// 等待匹配指定路径的 SO 加载
    ///
    /// # Arguments
    /// * `path_pattern` - 要匹配的路径模式（包含匹配）
    ///
    /// # Returns
    /// 匹配到的 DlopenInfo
    pub fn wait_for_path(&self, path_pattern: &str) -> Option<DlopenInfo> {
        while let Some(info) = self.recv() {
            if info.path.contains(path_pattern) {
                return Some(info);
            }
        }
        None
    }

    /// 等待匹配指定路径的 SO 加载（带超时）
    ///
    /// # Arguments
    /// * `path_pattern` - 要匹配的路径模式（包含匹配）
    /// * `timeout` - 超时时间
    ///
    /// # Returns
    /// 匹配到的 DlopenInfo，超时返回 None
    pub fn wait_for_path_timeout(&self, path_pattern: &str, timeout: std::time::Duration) -> Option<DlopenInfo> {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if let Ok(info) = self.receiver.recv_timeout(timeout - start.elapsed()) {
                if info.path.contains(path_pattern) {
                    return Some(info);
                }
            } else {
                break;
            }
        }
        None
    }
}

/// 从 /proc/uptime 读取内核运行秒数作为时间戳基线
fn get_kernel_uptime() -> f64 {
    if let Ok(content) = fs::read_to_string("/proc/uptime") {
        if let Some(first) = content.split_whitespace().next() {
            return first.parse::<f64>().unwrap_or(0.0);
        }
    }
    0.0
}

/// 从 dmesg 行中提取内核时间戳（格式: "[  123.456789] ..."）
fn parse_dmesg_timestamp(line: &str) -> Option<f64> {
    let start = line.find('[')? + 1;
    let end = line.find(']')?;
    line[start..end].trim().parse::<f64>().ok()
}

async fn run_monitor(
    _target_pid: Option<u32>,
    sender: Sender<DlopenInfo>,
    stop_flag: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;

    log::info!("Starting KPM dmesg log streaming backend...");

    // 记录启动基线：只接受此时间戳之后的 dmesg 行，过滤旧日志
    let baseline = get_kernel_uptime();
    log::info!("dmesg baseline uptime: {:.3}s", baseline);

    let mut child = Command::new("dmesg").arg("-w").stdout(Stdio::piped()).spawn()?;

    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout).lines();

    loop {
        if stop_flag.load(Ordering::SeqCst) {
            let _ = child.kill().await;
            break;
        }

        match reader.next_line().await {
            Ok(Some(line)) => {
                // 过滤旧日志：跳过时间戳早于基线的行
                if let Some(ts) = parse_dmesg_timestamp(&line) {
                    if ts < baseline {
                        continue;
                    }
                }

                // Parse line format: "[KPM-DLOPEN] | PID:1234 | UID:10200 | PATH:/data/app/..."
                if line.contains("[KPM-DLOPEN]") && line.contains("PATH:") {
                    let mut pid: u32 = 0;
                    let mut uid: u32 = 0;
                    let mut path = String::new();

                    for part in line.split('|') {
                        let part = part.trim();
                        if let Some(rest) = part.strip_prefix("PID:") {
                            pid = rest.trim().parse().unwrap_or(0);
                        } else if let Some(rest) = part.strip_prefix("UID:") {
                            uid = rest.trim().parse().unwrap_or(0);
                        } else if let Some(rest) = part.strip_prefix("PATH:") {
                            path = rest.trim().to_string();
                        }
                    }

                    if pid > 0 && !path.is_empty() {
                        // 验证进程仍然存活，避免旧 PID 导致注入失败
                        let proc_path = format!("/proc/{}", pid);
                        if !std::path::Path::new(&proc_path).exists() {
                            log::warn!("跳过已失效的 PID {}: {}", pid, path);
                            continue;
                        }

                        let info = DlopenInfo {
                            host_pid: pid,
                            ns_pid: None,
                            uid,
                            path,
                        };
                        if sender.send(info).is_err() {
                            break; // receiver dropped
                        }
                    }
                }
            }
            Ok(None) => break, // EOF
            Err(e) => {
                log::error!("Error reading dmesg output: {}", e);
                break;
            }
        }
    }

    Ok(())
}
