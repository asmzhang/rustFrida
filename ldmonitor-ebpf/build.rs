use which::which;

fn main() {
    if cfg!(windows) {
        println!("cargo:warning=Skipping bpf-linker lookup on Windows host; ldmonitor eBPF build is disabled.");
        return;
    }

    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}
