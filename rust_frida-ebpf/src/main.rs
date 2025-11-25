#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, uprobe},
    maps::PerfEventArray,
    programs::ProbeContext,
    EbpfContext,
};
use aya_log_ebpf::info;

/// Event structure for android_dlopen_ext calls
/// Matches the structure in ebpf_dlopen.rs
#[repr(C)]
pub struct DlopenEvent {
    pub pid: u32,
    pub tid: u32,
    pub filename_ptr: u64,
    pub flags: i32,
    pub extinfo_ptr: u64,
    pub caller_addr: u64,
}

/// Perf event array for sending events to user-space
#[map]
static DLOPEN_EVENTS: PerfEventArray<DlopenEvent> = PerfEventArray::new(0);

/// Uprobe for android_dlopen_ext entry point
///
/// Function signature (from Android bionic source):
/// ```c
/// void* android_dlopen_ext(const char* filename, int flags, const android_dlextinfo* extinfo)
/// ```
///
/// ARM64 calling convention:
/// - X0 (ctx.arg(0)): filename - pointer to the library path string
/// - X1 (ctx.arg(1)): flags - RTLD_* flags (RTLD_NOW, RTLD_LAZY, etc.)
/// - X2 (ctx.arg(2)): extinfo - pointer to android_dlextinfo structure
/// - X30 (LR): return address (caller address)
///
/// This uprobe captures all arguments and sends them to user-space for analysis.
#[uprobe]
pub fn android_dlopen_ext_entry(ctx: ProbeContext) -> u32 {
    match try_android_dlopen_ext_entry(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_android_dlopen_ext_entry(ctx: ProbeContext) -> Result<u32, i64> {
    // Read function arguments from ARM64 registers
    let filename_ptr: u64 = ctx.arg(0).ok_or(1i64)?;  // X0 - const char* filename
    let flags: i32 = ctx.arg(1).ok_or(1i64)?;         // X1 - int flags
    let extinfo_ptr: u64 = ctx.arg(2).ok_or(1i64)?;   // X2 - const android_dlextinfo*

    // Get process and thread identifiers
    let pid_tgid = ctx.pid();
    let pid = (pid_tgid >> 32) as u32;  // TGID (process ID)
    let tid = pid_tgid as u32;          // PID (thread ID)

    // Get caller address from user_pt_regs (ARM64)
    // The return address is stored in X30 (LR - Link Register)
    let caller_addr = unsafe {
        // Read X30 from pt_regs structure
        // Note: This is a simplified approach; actual implementation may vary
        // based on kernel version and probe context
        let regs_ptr = ctx.as_ptr() as *const u64;
        if !regs_ptr.is_null() {
            // X30 is typically at offset 30 in pt_regs for ARM64
            *regs_ptr.add(30)
        } else {
            0u64
        }
    };

    // Log the event for debugging (visible via /sys/kernel/debug/tracing/trace_pipe)
    info!(
        &ctx,
        "[android_dlopen_ext] PID: {} TID: {} | filename: 0x{:x} | flags: 0x{:x} | extinfo: 0x{:x} | caller: 0x{:x}",
        pid,
        tid,
        filename_ptr,
        flags,
        extinfo_ptr,
        caller_addr
    );

    // Create event structure to send to user-space
    let event = DlopenEvent {
        pid,
        tid,
        filename_ptr,
        flags,
        extinfo_ptr,
        caller_addr,
    };

    // Send event to user-space via perf event array
    DLOPEN_EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}