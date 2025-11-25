# rust_frida eBPF Uprobe for android_dlopen_ext

This directory contains an eBPF uprobe program that traces calls to `android_dlopen_ext` in Android's dynamic linker.

## Overview

The eBPF program attaches to `/apex/com.android.runtime/lib64/bionic/libdl.so:android_dlopen_ext` and captures:
- Process ID (PID) and Thread ID (TID)
- Filename pointer (library being loaded)
- Flags (RTLD_* flags)
- Extended info pointer
- Caller address (return address from X30/LR register)

## Prerequisites

### 1. Install bpf-linker

```bash
cargo install bpf-linker
```

### 2. Add eBPF target

```bash
rustup target add bpfel-unknown-none
```

## Building the eBPF Program

### Using Build Script (Recommended)

**Windows:**
```cmd
cd rust_frida-ebpf
build.bat
```

**Linux/macOS:**
```bash
cd rust_frida-ebpf
./build.sh
```

The build script will automatically:
- Install bpf-linker if needed
- Add the bpfel-unknown-none target if needed
- Compile the eBPF program in release mode
- Copy the output to `../dlopen_probe.o`

### Manual Build

**Development Build:**
```bash
cd rust_frida-ebpf
cargo build --target bpfel-unknown-none
```

The output will be at: `target/bpfel-unknown-none/debug/dlopen_probe`

**Release Build:**
```bash
cargo build --target bpfel-unknown-none --release
```

The output will be at: `target/bpfel-unknown-none/release/dlopen_probe`

## Using the eBPF Program

### Option 1: Load from File

After building the eBPF program, copy it to the main project:

```bash
cp target/bpfel-unknown-none/release/dlopen_probe ../dlopen_probe.o
```

Then run the user-space loader:

```rust
use rust_frida::ebpf_dlopen;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    ebpf_dlopen::run_dlopen_probe().await
}
```

### Option 2: Embed at Compile Time

Modify `rust_frida/src/ebpf_dlopen.rs` to use `include_bytes_aligned!`:

```rust
let ebpf_binary = include_bytes_aligned!(
    "../../rust_frida-ebpf/target/bpfel-unknown-none/release/dlopen_probe"
);
let mut probe = DlopenProbe::load(ebpf_binary)?;
```

## Event Structure

The eBPF program sends the following event structure to user-space:

```rust
#[repr(C)]
pub struct DlopenEvent {
    pub pid: u32,           // Process ID
    pub tid: u32,           // Thread ID
    pub filename_ptr: u64,  // Pointer to library path
    pub flags: i32,         // RTLD_* flags
    pub extinfo_ptr: u64,   // android_dlextinfo pointer
    pub caller_addr: u64,   // Caller address (from X30)
}
```

## ARM64 Calling Convention

The `android_dlopen_ext` function follows the ARM64 calling convention:

```c
void* android_dlopen_ext(const char* filename, int flags, const android_dlextinfo* extinfo)
```

| Argument | Register | Description |
|----------|----------|-------------|
| filename | X0       | Path to library file |
| flags    | X1       | RTLD_NOW, RTLD_LAZY, etc. |
| extinfo  | X2       | Extended info structure |
| Return   | X0       | Handle to loaded library |
| Caller   | X30 (LR) | Return address |

## Example Output

```
[+] eBPF uprobe attached to /apex/com.android.runtime/lib64/bionic/libdl.so:android_dlopen_ext
[DLOPEN] PID: 12345 TID: 12346 | filename: 0x7ff8a2b000 | flags: 0x1 | extinfo: 0x0 | caller: 0x7ff8a1c4f0
[DLOPEN] PID: 12345 TID: 12347 | filename: 0x7ff8a2c100 | flags: 0x2 | extinfo: 0x7ffd123400 | caller: 0x7ff8a1d560
```

## Troubleshooting

### Permission Denied

eBPF programs require root/CAP_BPF privileges:

```bash
# Run with root
sudo ./your_program

# Or grant CAP_BPF capability
sudo setcap cap_bpf+ep ./your_program
```

### Target Not Found

Ensure the target library path is correct for your Android device:

```bash
adb shell ls -la /apex/com.android.runtime/lib64/bionic/libdl.so
```

Different Android versions may have different paths:
- `/apex/com.android.runtime/lib64/bionic/libdl.so` (Android 10+)
- `/system/lib64/libdl.so` (older versions)

### Reading Filename String

To read the actual filename string from `filename_ptr`, you'll need to use `bpf_probe_read_user_str` in the eBPF program:

```rust
let mut filename = [0u8; 256];
unsafe {
    bpf_probe_read_user_str(
        filename.as_mut_ptr() as *mut _,
        filename.len() as u32,
        filename_ptr as *const _
    );
}
```

Then include `filename` in the `DlopenEvent` structure.

## References

- [aya Documentation](https://aya-rs.dev/)
- [eBPF Documentation](https://ebpf.io/)
- [Android Bionic Source](https://android.googlesource.com/platform/bionic/)
- [ARM64 Procedure Call Standard](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)