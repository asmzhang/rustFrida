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

fn get_current_pid_ns() -> Option<u64> {
    let link = fs::read_link("/proc/self/ns/pid").ok()?;
    let s = link.to_string_lossy();
    let start = s.find('[')? + 1;
    let end = s.find(']')?;
    s[start..end].parse().ok()
}

fn get_pid_ns(pid: u32) -> Option<u64> {
    let link = fs::read_link(format!("/proc/{}/ns/pid", pid)).ok()?;
    let s = link.to_string_lossy();
    let start = s.find('[')? + 1;
    let end = s.find(']')?;
    s[start..end].parse().ok()
}

pub fn translate_pid_to_current_ns(host_pid: u32) -> Option<u32> {
    let nspids = get_nspid(host_pid)?;

    if nspids.len() == 1 {
        return Some(nspids[0]);
    }

    let current_ns = get_current_pid_ns()?;
    let target_ns = get_pid_ns(host_pid)?;

    if current_ns == target_ns {
        return nspids.last().copied();
    }

    nspids.last().copied()
}

#[derive(Debug, Clone)]
pub struct DlopenInfo {
    pub host_pid: u32,
    pub ns_pid: Option<u32>,
    pub uid: u32,
    pub path: String,
}

impl DlopenInfo {
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

pub struct DlopenMonitor {
    receiver: Receiver<DlopenInfo>,
    stop_flag: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl DlopenMonitor {
    pub fn new(target_pid: Option<u32>) -> anyhow::Result<Self> {
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

    pub fn stop(self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        println!("KPM monitor stopped");
    }

    pub fn recv(&self) -> Option<DlopenInfo> {
        self.receiver.recv().ok()
    }

    pub fn try_recv(&self) -> Option<DlopenInfo> {
        self.receiver.try_recv().ok()
    }

    pub fn wait_for_path(&self, path_pattern: &str) -> Option<DlopenInfo> {
        while let Some(info) = self.recv() {
            if info.path.contains(path_pattern) {
                return Some(info);
            }
        }
        None
    }

    pub fn wait_for_path_timeout(
        &self,
        path_pattern: &str,
        timeout: std::time::Duration,
    ) -> Option<DlopenInfo> {
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

impl Drop for DlopenMonitor {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn get_kernel_uptime() -> f64 {
    if let Ok(content) = fs::read_to_string("/proc/uptime") {
        if let Some(first) = content.split_whitespace().next() {
            return first.parse::<f64>().unwrap_or(0.0);
        }
    }
    0.0
}

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
                if let Some(ts) = parse_dmesg_timestamp(&line) {
                    if ts < baseline {
                        continue;
                    }
                }

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
                        let proc_path = format!("/proc/{}", pid);
                        if !std::path::Path::new(&proc_path).exists() {
                            log::warn!("Skipping stale PID {}: {}", pid, path);
                            continue;
                        }

                        let info = DlopenInfo {
                            host_pid: pid,
                            ns_pid: translate_pid_to_current_ns(pid),
                            uid,
                            path,
                        };
                        if sender.send(info).is_err() {
                            break;
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                log::error!("Error reading dmesg output: {}", e);
                break;
            }
        }
    }

    Ok(())
}
