//! ldmonitor - KPM-based library loading monitor
//!
//! This library prefers a future `/dev/ldmonitor` backend, but on the current
//! verified KernelPatch deployments the primary working event path is:
//! KPM log emission -> `dmesg` -> ldmonitor.
//! The legacy KPM NetLink path is retained only as a last-resort compatibility
//! backend.

use anyhow::{bail, Context};
use log::debug;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, RawFd};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

pub use ldmonitor_common::{
    DlopenEvent, LdmFilter, LdmMsgHeader, LdmNlEvent, LDMON_CMD_HELLO, LDMON_CMD_SET_FILTER,
    LDMON_CMD_START, LDMON_MAGIC, LDMON_MAX_PATH_LEN, LDMON_NL_MSG_EVENT_DLOPEN,
    LDMON_NL_MSG_SUBSCRIBE, LDMON_NL_MSG_UNSUBSCRIBE, LDMON_NL_PROTO_FALLBACK,
    LDMON_NL_PROTO_PRIMARY, LDMON_NL_VERSION, LDMON_PROTO_VERSION, MAX_PATH_LEN,
};

const DEFAULT_LDMON_DEVICE_PATH: &str = "/dev/ldmonitor";
const LDMON_IOCTL_MAGIC: u8 = b'L';

const fn linux_iowr(nr: u8, size: usize) -> libc::c_ulong {
    ((2u64 << 30) | ((size as u64) << 16) | ((LDMON_IOCTL_MAGIC as u64) << 8) | nr as u64)
        as libc::c_ulong
}

const LDMON_IOCTL_HELLO: libc::Ioctl = linux_iowr(0x01, size_of::<LdmMsgHeader>()) as libc::Ioctl;
const LDMON_IOCTL_SET_FILTER: libc::Ioctl =
    linux_iowr(0x03, size_of::<DeviceFilterMessage>()) as libc::Ioctl;
const LDMON_IOCTL_START: libc::Ioctl = linux_iowr(0x04, size_of::<LdmMsgHeader>()) as libc::Ioctl;

fn ldmonitor_diag_enabled() -> bool {
    std::env::var_os("RUSTFRIDA_LDMONITOR_DEBUG").is_some()
}

macro_rules! ldmonitor_diag {
    ($($arg:tt)*) => {
        if ldmonitor_diag_enabled() {
            eprintln!("[ldmonitor] {}", format_args!($($arg)*));
        }
    };
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct DeviceFilterMessage {
    header: LdmMsgHeader,
    filter: LdmFilter,
}

struct DeviceMonitor {
    file: File,
}

struct LogcatMonitor {
    child: Child,
    stdout: ChildStdout,
    buf: Vec<u8>,
}

impl Drop for LogcatMonitor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

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
        Self {
            host_pid: event.pid,
            ns_pid: translate_pid_to_current_ns(event.pid),
            uid: event.uid,
            path: event.path_str().to_string(),
        }
    }
}

impl From<&LdmNlEvent> for DlopenInfo {
    fn from(event: &LdmNlEvent) -> Self {
        Self {
            host_pid: event.pid,
            ns_pid: translate_pid_to_current_ns(event.pid),
            uid: event.uid,
            path: event.path_str().to_string(),
        }
    }
}

struct NetlinkMonitorSocket {
    fd: RawFd,
    protocol: i32,
    portid: u32,
}

impl Drop for NetlinkMonitorSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
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
            if let Err(e) = run_monitor(target_pid, sender, stop_flag_clone) {
                eprintln!("Monitor error: {e}");
            }
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

fn ldmonitor_device_path() -> String {
    std::env::var("RUSTFRIDA_LDMONITOR_DEVICE").unwrap_or_else(|_| DEFAULT_LDMON_DEVICE_PATH.to_string())
}

fn encode_filter_message(target_pid: Option<u32>, path_pattern: &str) -> anyhow::Result<DeviceFilterMessage> {
    let mut filter = LdmFilter::empty();
    let path_bytes = path_pattern.as_bytes();
    let copy_len = path_bytes.len().min(MAX_PATH_LEN.saturating_sub(1));

    filter.target_pid = target_pid.unwrap_or(0);
    filter.path_substr_len = copy_len as u32;
    filter.path_substr[..copy_len].copy_from_slice(&path_bytes[..copy_len]);

    Ok(DeviceFilterMessage {
        header: LdmMsgHeader::new(LDMON_CMD_SET_FILTER, 0, size_of::<LdmFilter>() as u32),
        filter,
    })
}

fn parse_device_event(buf: &[u8]) -> anyhow::Result<DlopenEvent> {
    if buf.len() < size_of::<DlopenEvent>() {
        bail!("short device payload: {}", buf.len());
    }

    let event = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const DlopenEvent) };
    Ok(event)
}

fn send_device_ioctl<T>(file: &File, request: libc::Ioctl, payload: &mut T, label: &str) -> anyhow::Result<()> {
    let rc = unsafe { libc::ioctl(file.as_raw_fd(), request, payload as *mut T) };
    if rc != 0 {
        bail!("{label} ioctl failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

fn open_device_monitor(target_pid: Option<u32>, path_pattern: &str) -> anyhow::Result<DeviceMonitor> {
    let device_path = ldmonitor_device_path();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&device_path)
        .with_context(|| format!("open {} failed", device_path))?;

    let mut hello = LdmMsgHeader::new(LDMON_CMD_HELLO, 0, 0);
    send_device_ioctl(&file, LDMON_IOCTL_HELLO, &mut hello, "hello")?;

    let mut filter = encode_filter_message(target_pid, path_pattern)?;
    send_device_ioctl(&file, LDMON_IOCTL_SET_FILTER, &mut filter, "set_filter")?;

    let mut start = LdmMsgHeader::new(LDMON_CMD_START, 0, 0);
    send_device_ioctl(&file, LDMON_IOCTL_START, &mut start, "start")?;

    Ok(DeviceMonitor { file })
}

fn recv_device_event(
    monitor: &mut DeviceMonitor,
    stop_flag: &AtomicBool,
) -> anyhow::Result<Option<DlopenEvent>> {
    loop {
        if stop_flag.load(Ordering::SeqCst) {
            return Ok(None);
        }

        let mut pollfd = libc::pollfd {
            fd: monitor.file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_ret = unsafe { libc::poll(&mut pollfd, 1, 250) };
        if poll_ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(err).context("poll(device) failed");
        }
        if poll_ret == 0 || (pollfd.revents & libc::POLLIN) == 0 {
            continue;
        }

        let mut buf = [0u8; size_of::<DlopenEvent>()];
        match monitor.file.read_exact(&mut buf) {
            Ok(()) => return Ok(Some(parse_device_event(&buf)?)),
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(None),
            Err(err) => return Err(err).context("read(device event) failed"),
        }
    }
}

fn parse_kpm_log_line(line: &str) -> Option<DlopenInfo> {
    const PREFIX: &str = "[KPM-DLOPEN] | PID:";
    let start = line.find(PREFIX)?;
    let rest = &line[start + PREFIX.len()..];

    let (pid_str, rest) = rest.split_once(" | UID:")?;
    let (uid_str, path) = rest.split_once(" | PATH:")?;
    let host_pid = pid_str.trim().parse::<u32>().ok()?;
    let uid = uid_str.trim().parse::<u32>().ok()?;
    let path = path.trim();

    if host_pid == 0 || path.is_empty() {
        return None;
    }

    Some(DlopenInfo {
        host_pid,
        ns_pid: translate_pid_to_current_ns(host_pid),
        uid,
        path: path.to_string(),
    })
}

fn open_logcat_monitor() -> anyhow::Result<LogcatMonitor> {
    let mut child = Command::new("dmesg")
        .args(["-w"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn dmesg -w failed")?;
    let stdout = child.stdout.take().context("dmesg -w stdout unavailable")?;

    Ok(LogcatMonitor {
        child,
        stdout,
        buf: Vec::with_capacity(1024),
    })
}

fn recv_logcat_event(
    monitor: &mut LogcatMonitor,
    stop_flag: &AtomicBool,
) -> anyhow::Result<Option<DlopenInfo>> {
    loop {
        if stop_flag.load(Ordering::SeqCst) {
            return Ok(None);
        }

        let mut pollfd = libc::pollfd {
            fd: monitor.stdout.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_ret = unsafe { libc::poll(&mut pollfd, 1, 250) };
        if poll_ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(err).context("poll(dmesg) failed");
        }
        if poll_ret == 0 || (pollfd.revents & libc::POLLIN) == 0 {
            continue;
        }

        let mut tmp = [0u8; 1024];
        let read_len = match monitor.stdout.read(&mut tmp) {
            Ok(0) => return Ok(None),
            Ok(n) => n,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(err).context("read(dmesg) failed"),
        };
        monitor.buf.extend_from_slice(&tmp[..read_len]);

        while let Some(newline_pos) = monitor.buf.iter().position(|b| *b == b'\n') {
            let line = String::from_utf8_lossy(&monitor.buf[..newline_pos]).to_string();
            monitor.buf.drain(..=newline_pos);

            if let Some(info) = parse_kpm_log_line(&line) {
                return Ok(Some(info));
            }
        }
    }
}

fn bind_netlink_socket(protocol: i32) -> anyhow::Result<NetlinkMonitorSocket> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, protocol) };
    if fd < 0 {
        bail!(
            "socket(AF_NETLINK, SOCK_RAW, proto={protocol}) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    let mut addr: libc::sockaddr_nl = unsafe { zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = 0;
    addr.nl_groups = 0;

    let bind_ret = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bind_ret != 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        bail!("bind(netlink, proto={protocol}) failed: {err}");
    }

    let mut local: libc::sockaddr_nl = unsafe { zeroed() };
    let mut len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    let name_ret = unsafe {
        libc::getsockname(
            fd,
            &mut local as *mut _ as *mut libc::sockaddr,
            &mut len,
        )
    };
    if name_ret != 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        bail!("getsockname(netlink, proto={protocol}) failed: {err}");
    }

    Ok(NetlinkMonitorSocket {
        fd,
        protocol,
        portid: local.nl_pid,
    })
}

fn send_netlink_control(sock: &NetlinkMonitorSocket, msg_type: u32) -> anyhow::Result<()> {
    let hdr_len = size_of::<libc::nlmsghdr>();
    let payload_len = size_of::<LdmNlEvent>();
    let total_len = hdr_len + payload_len;
    let mut buf = vec![0u8; total_len];

    let hdr = libc::nlmsghdr {
        nlmsg_len: total_len as u32,
        nlmsg_type: libc::NLMSG_DONE as u16,
        nlmsg_flags: 0,
        nlmsg_seq: 0,
        nlmsg_pid: sock.portid,
    };

    let event = LdmNlEvent {
        version: LDMON_NL_VERSION,
        msg_type,
        pid: 0,
        uid: 0,
        path_len: 0,
        reserved: 0,
        path: [0; LDMON_MAX_PATH_LEN],
    };

    unsafe {
        std::ptr::copy_nonoverlapping(&hdr as *const _ as *const u8, buf.as_mut_ptr(), hdr_len);
        std::ptr::copy_nonoverlapping(
            &event as *const _ as *const u8,
            buf.as_mut_ptr().add(hdr_len),
            payload_len,
        );
    }

    let mut kernel: libc::sockaddr_nl = unsafe { zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;
    kernel.nl_pid = 0;
    kernel.nl_groups = 0;

    let ret = unsafe {
        libc::sendto(
            sock.fd,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            0,
            &kernel as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        bail!(
            "sendto(netlink control type={msg_type}, proto={}) failed: {}",
            sock.protocol,
            std::io::Error::last_os_error()
        );
    }

    Ok(())
}

fn parse_netlink_event(buf: &[u8]) -> anyhow::Result<LdmNlEvent> {
    let hdr_len = size_of::<libc::nlmsghdr>();
    let event_len = size_of::<LdmNlEvent>();
    if buf.len() < hdr_len {
        bail!("short netlink header: {}", buf.len());
    }

    let hdr = unsafe { &*(buf.as_ptr() as *const libc::nlmsghdr) };
    let total_len = hdr.nlmsg_len as usize;
    if total_len < hdr_len + event_len {
        bail!("short netlink payload: {}", total_len);
    }
    if buf.len() < total_len {
        bail!("truncated recv buffer: have={}, want={total_len}", buf.len());
    }

    let event_ptr = unsafe { buf.as_ptr().add(hdr_len) as *const LdmNlEvent };
    let event = unsafe { *event_ptr };
    Ok(event)
}

fn recv_netlink_event(
    sock: &NetlinkMonitorSocket,
    stop_flag: &AtomicBool,
) -> anyhow::Result<Option<LdmNlEvent>> {
    loop {
        if stop_flag.load(Ordering::SeqCst) {
            return Ok(None);
        }

        let mut pollfd = libc::pollfd {
            fd: sock.fd,
            events: libc::POLLIN,
            revents: 0,
        };

        let poll_ret = unsafe { libc::poll(&mut pollfd, 1, 250) };
        if poll_ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err).context("poll(netlink) failed");
        }

        if poll_ret == 0 {
            continue;
        }

        if (pollfd.revents & libc::POLLIN) == 0 {
            continue;
        }

        let mut buf = [0u8; 512];
        let recv_len = unsafe {
            libc::recv(
                sock.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if recv_len < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err).context("recv(netlink) failed");
        }

        let event = parse_netlink_event(&buf[..recv_len as usize])?;
        return Ok(Some(event));
    }
}

fn run_monitor(
    target_pid: Option<u32>,
    sender: Sender<DlopenInfo>,
    stop_flag: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let path_pattern = std::env::var("RUSTFRIDA_LDMONITOR_FILTER").unwrap_or_else(|_| ".so".to_string());

    if let Ok(mut monitor) = open_device_monitor(target_pid, &path_pattern) {
        log::info!("Starting KPM device backend...");
        loop {
            let Some(event) = recv_device_event(&mut monitor, &stop_flag)? else {
                break;
            };

            if event.pid == 0 || event.path_str().is_empty() {
                ldmonitor_diag!("skip invalid device event pid={} path={}", event.pid, event.path_str());
                continue;
            }

            let info = DlopenInfo::from(&event);
            if sender.send(info).is_err() {
                ldmonitor_diag!("receiver dropped");
                break;
            }
        }
        return Ok(());
    }

    if let Ok(mut monitor) = open_logcat_monitor() {
        log::info!("Starting KPM dmesg backend...");
        loop {
            let Some(info) = recv_logcat_event(&mut monitor, &stop_flag)? else {
                break;
            };

            if sender.send(info).is_err() {
                ldmonitor_diag!("receiver dropped");
                break;
            }
        }
        return Ok(());
    }

    log::info!("Starting KPM netlink backend...");

    let sock = match bind_netlink_socket(LDMON_NL_PROTO_PRIMARY) {
        Ok(sock) => sock,
        Err(primary_err) => {
            ldmonitor_diag!("primary proto failed: {primary_err}");
            bind_netlink_socket(LDMON_NL_PROTO_FALLBACK).with_context(|| {
                format!(
                    "failed to bind netlink protocols {} and {}",
                    LDMON_NL_PROTO_PRIMARY, LDMON_NL_PROTO_FALLBACK
                )
            })?
        }
    };

    log::info!(
        "ldmonitor netlink connected: proto={}, portid={}",
        sock.protocol,
        sock.portid
    );
    send_netlink_control(&sock, LDMON_NL_MSG_SUBSCRIBE)?;

    let result = (|| -> anyhow::Result<()> {
        loop {
            let Some(event) = recv_netlink_event(&sock, &stop_flag)? else {
                break;
            };

            if event.version != LDMON_NL_VERSION {
                ldmonitor_diag!("skip version={} expected={}", event.version, LDMON_NL_VERSION);
                continue;
            }

            if event.msg_type != LDMON_NL_MSG_EVENT_DLOPEN {
                ldmonitor_diag!("skip msg_type={}", event.msg_type);
                continue;
            }

            if event.pid == 0 || event.path_str().is_empty() {
                ldmonitor_diag!("skip invalid event pid={} path={}", event.pid, event.path_str());
                continue;
            }

            let proc_path = format!("/proc/{}", event.pid);
            if !std::path::Path::new(&proc_path).exists() {
                ldmonitor_diag!("skip stale pid={} path={}", event.pid, event.path_str());
                continue;
            }

            let info = DlopenInfo::from(&event);
            ldmonitor_diag!(
                "emit host_pid={} ns_pid={:?} uid={} path={}",
                info.host_pid,
                info.ns_pid,
                info.uid,
                info.path
            );

            if sender.send(info).is_err() {
                ldmonitor_diag!("receiver dropped");
                break;
            }
        }
        Ok(())
    })();

    let _ = send_netlink_control(&sock, LDMON_NL_MSG_UNSUBSCRIBE);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldmonitor_common::{LdmFilter, LDMON_CMD_SET_FILTER, LDMON_MAGIC, LDMON_PROTO_VERSION};

    fn encode_event(event: &LdmNlEvent) -> Vec<u8> {
        let hdr_len = std::mem::size_of::<libc::nlmsghdr>();
        let payload_len = std::mem::size_of::<LdmNlEvent>();
        let mut buf = vec![0u8; hdr_len + payload_len];

        let hdr = libc::nlmsghdr {
            nlmsg_len: (hdr_len + payload_len) as u32,
            nlmsg_type: libc::NLMSG_DONE as u16,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 1234,
        };

        unsafe {
            std::ptr::copy_nonoverlapping(&hdr as *const _ as *const u8, buf.as_mut_ptr(), hdr_len);
            std::ptr::copy_nonoverlapping(
                event as *const _ as *const u8,
                buf.as_mut_ptr().add(hdr_len),
                payload_len,
            );
        }

        buf
    }

    #[test]
    fn parse_netlink_event_accepts_valid_packet() {
        let mut event = LdmNlEvent {
            version: LDMON_NL_VERSION,
            msg_type: LDMON_NL_MSG_EVENT_DLOPEN,
            pid: 4321,
            uid: 10000,
            path_len: 24,
            reserved: 0,
            path: [0; LDMON_MAX_PATH_LEN],
        };
        event.path[..24].copy_from_slice(b"/data/app/lib/libfoo.so");

        let parsed = parse_netlink_event(&encode_event(&event)).expect("valid packet");
        assert_eq!(parsed.pid, 4321);
        assert_eq!(parsed.uid, 10000);
        assert_eq!(parsed.path_str(), "/data/app/lib/libfoo.so");
    }

    #[test]
    fn parse_netlink_event_rejects_short_packet() {
        let err = parse_netlink_event(&[0u8; 8]).unwrap_err().to_string();
        assert!(err.contains("short"));
    }

    #[test]
    fn encode_filter_message_sets_header_and_payload() {
        let msg = encode_filter_message(Some(4321), "libnative-lib.so").expect("filter message");

        assert_eq!(msg.header.magic, LDMON_MAGIC);
        assert_eq!(msg.header.version, LDMON_PROTO_VERSION);
        assert_eq!(msg.header.cmd, LDMON_CMD_SET_FILTER);
        assert_eq!(msg.header.len as usize, std::mem::size_of::<LdmFilter>());
        assert_eq!(msg.filter.target_pid, 4321);
        assert_eq!(msg.filter.path_substr(), "libnative-lib.so");
    }

    #[test]
    fn parse_device_event_accepts_exact_payload() {
        let mut event = DlopenEvent {
            pid: 777,
            uid: 10001,
            path_len: 24,
            path: [0; MAX_PATH_LEN],
        };
        event.path[..24].copy_from_slice(b"/data/app/lib/libbar.so");

        let bytes = unsafe {
            std::slice::from_raw_parts(
                &event as *const _ as *const u8,
                std::mem::size_of::<DlopenEvent>(),
            )
        };

        let parsed = parse_device_event(bytes).expect("device event");
        assert_eq!(parsed.pid, 777);
        assert_eq!(parsed.uid, 10001);
        assert_eq!(parsed.path_str(), "/data/app/lib/libbar.so");
    }

    #[test]
    fn parse_device_event_rejects_short_payload() {
        let err = parse_device_event(&[0u8; 12]).unwrap_err().to_string();
        assert!(err.contains("short device payload"));
    }

    #[test]
    fn parse_kpm_log_line_extracts_dlopen_event() {
        let line = "[105568.457247] [KPM-DLOPEN] | PID:10732 | UID:10249 | PATH:/data/app/com.asmzhang.testapp/lib/arm64/libtestapp.so";

        let parsed = parse_kpm_log_line(line).expect("parsed");
        assert_eq!(parsed.host_pid, 10732);
        assert_eq!(parsed.uid, 10249);
        assert_eq!(
            parsed.path,
            "/data/app/com.asmzhang.testapp/lib/arm64/libtestapp.so"
        );
    }

    #[test]
    fn parse_kpm_log_line_ignores_control_messages() {
        let line = "[105536.413755] [KPM-DLOPEN] ctl0 start";
        assert!(parse_kpm_log_line(line).is_none());
    }
}
