/*!
 * eBPF Uprobe for android_dlopen_ext
 *
 * This module implements an eBPF-based uprobe to trace calls to android_dlopen_ext
 * in /apex/com.android.runtime/lib64/bionic/libdl.so
 *
 * Architecture:
 * 1. eBPF program (kernel space) - attaches to android_dlopen_ext and captures arguments
 * 2. User-space loader (this file) - loads the eBPF program and reads events
 *
 * Note: The eBPF program needs to be compiled separately with:
 * - Target: bpfel-unknown-none
 * - Linker: bpf-linker
 * - rustup target add bpfel-unknown-none
 * - cargo install bpf-linker
 */

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::UProbe,
    util::online_cpus,
    Bpf,
};
use aya_log::BpfLogger;
use bytes::BytesMut;
use std::path::Path;
use tokio::task;

/// Target library path on Android
const TARGET_LIB: &str = "/apex/com.android.runtime/lib64/bionic/libdl.so";

/// Target function to probe
const TARGET_FUNCTION: &str = "android_dlopen_ext";

/// Event structure matching the eBPF program output
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DlopenEvent {
    pub pid: u32,
    pub tid: u32,
    pub filename_ptr: u64,
    pub flags: i32,
    pub extinfo_ptr: u64,
    pub caller_addr: u64,
}

/// Main loader that attaches the uprobe and processes events
pub struct DlopenProbe {
    bpf: Bpf,
}

impl DlopenProbe {
    /// Load and attach the eBPF program
    pub fn load(ebpf_binary: &[u8]) -> Result<Self> {
        // Load the eBPF program
        let mut bpf = Bpf::load(ebpf_binary)?;

        // Initialize eBPF logger (optional, for debugging)
        if let Err(e) = BpfLogger::init(&mut bpf) {
            eprintln!("Warning: failed to initialize eBPF logger: {}", e);
        }

        // Get the uprobe program
        let program: &mut UProbe = bpf
            .program_mut("android_dlopen_ext_entry")
            .context("Failed to find uprobe program")?
            .try_into()?;

        // Load the program into the kernel
        program.load()?;

        // Attach to android_dlopen_ext in libdl.so
        program.attach(Some(TARGET_FUNCTION), 0, TARGET_LIB, None)?;

        println!("[+] eBPF uprobe attached to {}:{}", TARGET_LIB, TARGET_FUNCTION);

        Ok(Self { bpf })
    }

    /// Process events from the perf event array
    pub async fn process_events(&mut self) -> Result<()> {
        let mut perf_array = AsyncPerfEventArray::try_from(
            self.bpf.take_map("DLOPEN_EVENTS").context("Failed to get events map")?
        )?;

        // Create a task for each online CPU to read events
        let cpus = online_cpus()?;
        let mut tasks = Vec::new();

        for cpu_id in cpus {
            let mut buf = perf_array.open(cpu_id, None)?;

            let task = task::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(std::mem::size_of::<DlopenEvent>()))
                    .collect::<Vec<_>>();

                loop {
                    let events = buf.read_events(&mut buffers).await.unwrap();

                    for buf in buffers.iter_mut().take(events.read) {
                        let ptr = buf.as_ptr() as *const DlopenEvent;
                        let event = unsafe { ptr.read_unaligned() };

                        println!(
                            "[DLOPEN] PID: {} TID: {} | filename: 0x{:x} | flags: 0x{:x} | extinfo: 0x{:x} | caller: 0x{:x}",
                            event.pid,
                            event.tid,
                            event.filename_ptr,
                            event.flags,
                            event.extinfo_ptr,
                            event.caller_addr
                        );
                    }
                }
            });

            tasks.push(task);
        }

        // Wait for all tasks (runs indefinitely)
        for task in tasks {
            task.await?;
        }

        Ok(())
    }

    /// Detach the uprobe
    pub fn detach(&mut self) -> Result<()> {
        println!("[+] Detaching eBPF uprobe");
        // Bpf drop will automatically clean up
        Ok(())
    }
}

/// Example usage function
pub async fn run_dlopen_probe() -> Result<()> {
    // Load the compiled eBPF program
    // In a real setup, this would be the compiled .o file from the eBPF program
    // For now, we'll expect it to be embedded or loaded from disk

    // Option 1: Embedded at compile time (requires the eBPF program to be compiled first)
    // let ebpf_binary = include_bytes_aligned!("../target/bpfel-unknown-none/release/dlopen_probe");

    // Option 2: Load from file
    let ebpf_path = Path::new("./dlopen_probe.o");
    if !ebpf_path.exists() {
        anyhow::bail!("eBPF program not found at {:?}. Please compile the eBPF program first.", ebpf_path);
    }

    let ebpf_binary = std::fs::read(ebpf_path)?;

    // Load and attach the probe
    let mut probe = DlopenProbe::load(&ebpf_binary)?;

    // Process events (runs until interrupted)
    probe.process_events().await?;

    Ok(())
}

/*
 * ===========================
 * eBPF PROGRAM CODE (Separate Crate)
 * ===========================
 *
 * The following code should be in a separate crate (e.g., rust_frida-ebpf/)
 * and compiled with:
 *
 * cargo build --target bpfel-unknown-none --release
 *
 * Create a new crate with:
 * cargo new --lib rust_frida-ebpf
 *
 * File: rust_frida-ebpf/src/lib.rs
 * -----------------------------------
 *
 * #![no_std]
 * #![no_main]
 *
 * use aya_bpf::{
 *     macros::{map, uprobe},
 *     maps::PerfEventArray,
 *     programs::ProbeContext,
 * };
 * use aya_log_ebpf::info;
 *
 * /// Event structure for android_dlopen_ext calls
 * #[repr(C)]
 * pub struct DlopenEvent {
 *     pub pid: u32,
 *     pub tid: u32,
 *     pub filename_ptr: u64,
 *     pub flags: i32,
 *     pub extinfo_ptr: u64,
 *     pub caller_addr: u64,
 * }
 *
 * /// Perf event array for sending events to user-space
 * #[map]
 * static DLOPEN_EVENTS: PerfEventArray<DlopenEvent> = PerfEventArray::new(0);
 *
 * /// Uprobe for android_dlopen_ext entry
 * ///
 * /// Function signature (from Android source):
 * /// void* android_dlopen_ext(const char* filename, int flags, const android_dlextinfo* extinfo)
 * ///
 * /// ARM64 calling convention:
 * /// - X0: filename (const char*)
 * /// - X1: flags (int)
 * /// - X2: extinfo (const android_dlextinfo*)
 * /// - X30 (LR): return address / caller
 * #[uprobe]
 * pub fn android_dlopen_ext_entry(ctx: ProbeContext) -> u32 {
 *     match try_android_dlopen_ext_entry(ctx) {
 *         Ok(ret) => ret,
 *         Err(_) => 1,
 *     }
 * }
 *
 * fn try_android_dlopen_ext_entry(ctx: ProbeContext) -> Result<u32, i64> {
 *     // Read arguments from registers (ARM64 ABI)
 *     let filename_ptr: u64 = ctx.arg(0).ok_or(1i64)?;  // X0
 *     let flags: i32 = ctx.arg(1).ok_or(1i64)?;         // X1
 *     let extinfo_ptr: u64 = ctx.arg(2).ok_or(1i64)?;   // X2
 *
 *     // Get process/thread IDs
 *     let pid = (ctx.pid() >> 32) as u32;
 *     let tid = ctx.pid() as u32;
 *
 *     // Get return address (caller)
 *     // For ARM64, this would typically be in X30 (LR register)
 *     // However, ProbeContext doesn't directly expose this
 *     // We can use PT_REGS to read it if needed
 *     let caller_addr = 0u64; // TODO: Read from PT_REGS if needed
 *
 *     // Log the event
 *     info!(
 *         &ctx,
 *         "android_dlopen_ext called: pid={} tid={} filename=0x{:x} flags=0x{:x}",
 *         pid, tid, filename_ptr, flags
 *     );
 *
 *     // Create event
 *     let event = DlopenEvent {
 *         pid,
 *         tid,
 *         filename_ptr,
 *         flags,
 *         extinfo_ptr,
 *         caller_addr,
 *     };
 *
 *     // Send event to user-space
 *     DLOPEN_EVENTS.output(&ctx, &event, 0);
 *
 *     Ok(0)
 * }
 *
 * #[panic_handler]
 * fn panic(_info: &core::panic::PanicInfo) -> ! {
 *     unsafe { core::hint::unreachable_unchecked() }
 * }
 *
 * -----------------------------------
 *
 * File: rust_frida-ebpf/Cargo.toml
 * -----------------------------------
 *
 * [package]
 * name = "rust_frida-ebpf"
 * version = "0.1.0"
 * edition = "2021"
 *
 * [dependencies]
 * aya-bpf = "0.1"
 * aya-log-ebpf = "0.1"
 *
 * [profile.dev]
 * opt-level = 3
 * debug = false
 *
 * [profile.release]
 * opt-level = 3
 * debug = false
 * lto = true
 *
 * [[bin]]
 * name = "dlopen_probe"
 * path = "src/lib.rs"
 *
 * -----------------------------------
 *
 * Build instructions:
 *
 * 1. Install bpf-linker:
 *    cargo install bpf-linker
 *
 * 2. Add bpfel target:
 *    rustup target add bpfel-unknown-none
 *
 * 3. Build the eBPF program:
 *    cd rust_frida-ebpf
 *    cargo build --target bpfel-unknown-none --release
 *
 * 4. The compiled .o file will be at:
 *    target/bpfel-unknown-none/release/dlopen_probe
 *
 * 5. Copy it to the main project or embed it using include_bytes_aligned!
 */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_size() {
        // Ensure event struct is correctly sized for C interop
        assert_eq!(
            std::mem::size_of::<DlopenEvent>(),
            4 + 4 + 8 + 4 + 4 + 8 + 8 // pid + tid + filename + flags + padding + extinfo + caller
        );
    }
}