use std::path::{Path, PathBuf};

fn detect_ndk_root() -> Option<PathBuf> {
    for key in ["NDK_PATH", "ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"] {
        if let Ok(value) = std::env::var(key) {
            let path = PathBuf::from(value);
            if path.join("toolchains/llvm/prebuilt").is_dir() {
                return Some(path);
            }
        }
    }

    if let Ok(android_home) = std::env::var("ANDROID_HOME").or_else(|_| std::env::var("ANDROID_SDK_ROOT")) {
        let ndk_dir = Path::new(&android_home).join("ndk");
        if let Ok(entries) = std::fs::read_dir(ndk_dir) {
            let mut versions: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|entry| entry.path())).collect();
            versions.sort();
            versions.reverse();
            if let Some(path) = versions
                .into_iter()
                .find(|candidate| candidate.join("toolchains/llvm/prebuilt").is_dir())
            {
                return Some(path);
            }
        }
    }

    None
}

fn detect_host_tag(ndk_root: &Path) -> Option<&'static str> {
    [
        "windows-x86_64",
        "linux-x86_64",
        "darwin-arm64",
        "darwin-x86_64",
    ]
    .into_iter()
    .find(|tag| ndk_root.join("toolchains/llvm/prebuilt").join(tag).is_dir())
}

fn main() {
    cc::Build::new()
        .file("../agent/src/hide_soinfo.c")
        .compile("hide_soinfo");

    let manifest_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let workspace_root = manifest_dir
        .parent()
        .expect("qbdi-helper must live under the workspace root");
    let qbdi_archive = workspace_root.join("qbdi/libQBDI.a");

    println!("cargo:rustc-cdylib-link-arg={}", qbdi_archive.display());
    println!("cargo:rustc-link-lib=log");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_os == "android" && target_arch == "aarch64" {
        let ndk_root = detect_ndk_root().expect("Android NDK not found. Set NDK_PATH/ANDROID_NDK_HOME/ANDROID_NDK_ROOT.");
        let host_tag = detect_host_tag(&ndk_root).expect("No supported NDK prebuilt host tag found.");
        let cxx_lib_dir = ndk_root.join("toolchains/llvm/prebuilt").join(host_tag).join("sysroot/usr/lib/aarch64-linux-android");
        let cxx_static = cxx_lib_dir.join("libc++_static.a");
        let cxxabi = cxx_lib_dir.join("libc++abi.a");
        assert!(cxx_static.is_file(), "missing {}", cxx_static.display());
        assert!(cxxabi.is_file(), "missing {}", cxxabi.display());

        println!("cargo:rustc-cdylib-link-arg={}", cxx_static.display());
        println!("cargo:rustc-cdylib-link-arg={}", cxxabi.display());
        println!("cargo:rustc-link-lib=dylib=c");
        println!("cargo:rustc-link-lib=dylib=dl");
        println!("cargo:rustc-link-lib=dylib=m");
    } else {
        println!("cargo:rustc-link-lib=c++");
    }

    println!(
        "cargo:rustc-cdylib-link-arg=-Wl,-u,get_hide_result,-u,rust_get_hide_result,--export-dynamic-symbol=get_hide_result,--export-dynamic-symbol=rust_get_hide_result"
    );
    println!("cargo:rerun-if-changed=../agent/src/hide_soinfo.c");
    println!("cargo:rerun-if-changed={}", qbdi_archive.display());
    println!("cargo:rerun-if-env-changed=NDK_PATH");
    println!("cargo:rerun-if-env-changed=ANDROID_NDK_HOME");
    println!("cargo:rerun-if-env-changed=ANDROID_NDK_ROOT");
    println!("cargo:rerun-if-env-changed=ANDROID_HOME");
    println!("cargo:rerun-if-env-changed=ANDROID_SDK_ROOT");
}
