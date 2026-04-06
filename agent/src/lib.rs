#![cfg(all(target_os = "android", target_arch = "aarch64"))]

/// 生成 UnsafeCell 包装结构体，自动实现 Send + Sync。
/// 用于将非 Send/Sync 类型安全地存入 OnceLock 全局变量。
#[cfg(any(feature = "frida-gum", feature = "qbdi"))]
macro_rules! define_sync_cell {
    ($name:ident, $inner:ty) => {
        struct $name(std::cell::UnsafeCell<$inner>);
        unsafe impl Sync for $name {}
        unsafe impl Send for $name {}
    };
}

// === 【模块声明区】 ===
// 网络通信层：负责原生 socket 通信与帧装配
pub mod net;
// 底层系统交互层：负责崩溃捕获、内存分配包装等 OS 级别功能
pub mod sys;
// 核心执行引擎层：负责指令重现、代码提权 (recompiler)、跟踪 (stalker)
pub mod engine;
// 业务功能特性层：内存导出、JS 引擎等高级封装
pub mod features;
// 指令流水分发层：
pub mod router;

use crate::net::communication::{
    flush_cached_logs, is_cmd_frame, is_qbdi_helper_frame, log_msg, read_frame, register_stream_fd, send_complete,
    send_eval_err, send_eval_ok, send_hello, shutdown_stream, start_log_writer, write_stream, GLOBAL_STREAM,
};
use crate::sys::crash_handler::{install_crash_handlers, install_panic_hook};
use std::ffi::c_void;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

// hide_soinfo.c 中的调试结果函数（.init_array 构造函数填充）
// 通过 Rust #[no_mangle] 重导出到动态符号表，供 host 端 dlsym 查询
extern "C" {
    fn get_hide_result() -> *const c_void;
}

#[no_mangle]
pub extern "C" fn rust_get_hide_result() -> *const c_void {
    unsafe { get_hide_result() }
}

// 定义我们自己的Result类型
type Result<T> = std::result::Result<T, String>;

// StringTable 结构定义
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StringTable {
    pub sym_name: u64,
    pub sym_name_len: u32,
    pub pthread_err: u64,
    pub pthread_err_len: u32,
    pub dlsym_err: u64,
    pub dlsym_err_len: u32,
    pub cmdline: u64,
    pub cmdline_len: u32,
    pub output_path: u64,
    pub output_path_len: u32,
}

impl StringTable {
    unsafe fn read_string(&self, addr: u64, len: u32) -> Option<String> {
        if addr == 0 || len == 0 {
            return None;
        }
        let ptr = addr as *const u8;
        let slice = std::slice::from_raw_parts(ptr, len as usize);
        let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
        String::from_utf8(slice[..end].to_vec()).ok()
    }
    pub unsafe fn get_cmdline(&self) -> Option<String> {
        self.read_string(self.cmdline, self.cmdline_len)
    }
    pub unsafe fn get_output_path(&self) -> Option<String> {
        self.read_string(self.output_path, self.output_path_len)
    }
}

pub static SHOULD_EXIT: AtomicBool = AtomicBool::new(false);
pub static OUTPUT_PATH: OnceLock<String> = OnceLock::new();

#[repr(C)]
pub struct AgentArgs {
    pub table: u64,
    pub ctrl_fd: i32,
    pub agent_memfd: i32,
}

// 注入代理入口 (hello_entry)
// 目标进程被注入 `.so` 后，外部 (Loader或Host) 将会调用这个导出函数。
#[no_mangle]
pub extern "C" fn hello_entry(args_ptr: *mut c_void) -> *mut c_void {
    // 安装Rust panic hook（捕获Rust层面的panic，避免应用闪退无日志）
    install_panic_hook();
    // 安装 C 层的 Signal 崩溃捕获器
    install_crash_handlers();

    let (ctrl_fd, table) = unsafe {
        let args = &*(args_ptr as *const AgentArgs);
        (args.ctrl_fd, &*(args.table as *const StringTable))
    };

    unsafe {
        if let Some(output) = table.get_output_path() {
            if output != "novalue" {
                let _ = OUTPUT_PATH.set(output.clone());
            }
        }
        if let Some(cmd) = table.get_cmdline() {
            if cmd != "novalue" {
                crate::router::dispatch(&cmd);
            }
        }
    }

    let sock = unsafe { UnixStream::from_raw_fd(ctrl_fd) };
    let write_half = sock.try_clone().expect("stream clone failed");
    register_stream_fd(&write_half);
    GLOBAL_STREAM.set(std::sync::Mutex::new(write_half)).unwrap();
    start_log_writer();
    send_hello();
    std::thread::sleep(Duration::from_millis(100));
    flush_cached_logs();

    let mut reader = sock;
    loop {
        match read_frame(&mut reader) {
            Ok((kind, payload)) => {
                if is_cmd_frame(kind) {
                    let cmd = String::from_utf8_lossy(&payload).trim().to_string();
                    if !cmd.is_empty() {
                        crate::router::dispatch(&cmd);
                    }
                } else if is_qbdi_helper_frame(kind) {
                    #[cfg(feature = "quickjs")]
                    crate::features::quickjs_loader::install_qbdi_helper(payload);
                } else {
                    write_stream(format!("未知 frame kind: {}", kind).as_bytes());
                }
                if SHOULD_EXIT.load(Ordering::Relaxed) {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                write_stream(format!("读取命令错误: {}", e).as_bytes());
                break;
            }
        }
    }
    shutdown_stream();
    null_mut()
}
