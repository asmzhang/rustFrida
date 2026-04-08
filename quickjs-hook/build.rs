use std::env;
use std::path::{Path, PathBuf};

fn split_clang_args(args: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escape = false;

    for ch in args.chars() {
        if escape {
            current.push(ch);
            escape = false;
            continue;
        }

        if ch == '\\' {
            escape = true;
            continue;
        }

        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }

        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            continue;
        }

        if ch.is_whitespace() {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            continue;
        }

        current.push(ch);
    }

    if !current.is_empty() {
        out.push(current);
    }

    out
}

fn append_clang_args(mut builder: bindgen::Builder, args: &str) -> bindgen::Builder {
    for arg in split_clang_args(args) {
        builder = builder.clang_arg(arg);
    }
    builder
}

fn android_target_triple(target: &str) -> Option<&'static str> {
    match target {
        "aarch64-linux-android" => Some("aarch64-linux-android"),
        "armv7-linux-androideabi" => Some("arm-linux-androideabi"),
        "i686-linux-android" => Some("i686-linux-android"),
        "x86_64-linux-android" => Some("x86_64-linux-android"),
        _ => None,
    }
}

fn android_cxx_sysroot_lib_dir(ndk_root: &Path, target: &str) -> Option<PathBuf> {
    let host_tag = detect_host_tag(ndk_root)?;
    let triple = android_target_triple(target)?;
    let dir = ndk_root
        .join("toolchains")
        .join("llvm")
        .join("prebuilt")
        .join(host_tag)
        .join("sysroot")
        .join("usr")
        .join("lib")
        .join(triple);
    if dir.is_dir() { Some(dir) } else { None }
}

fn android_cxx_static_libs(ndk_root: &Path, target: &str) -> Option<(PathBuf, PathBuf)> {
    let dir = android_cxx_sysroot_lib_dir(ndk_root, target)?;
    let cxx_static = dir.join("libc++_static.a");
    let cxxabi = dir.join("libc++abi.a");
    if cxx_static.is_file() && cxxabi.is_file() {
        Some((cxx_static, cxxabi))
    } else {
        None
    }
}

fn detect_ndk_from_cc(target: &str) -> Option<PathBuf> {
    let env_names = [format!("CC_{}", target), format!("CC_{}", target.replace('-', "_"))];

    for env_name in env_names {
        if let Ok(cc) = env::var(&env_name) {
            let path = PathBuf::from(cc);
            let bin_dir = path.parent()?;
            let host_dir = bin_dir.parent()?;
            let prebuilt_dir = host_dir.parent()?;
            let llvm_dir = prebuilt_dir.parent()?;
            let toolchains_dir = llvm_dir.parent()?;
            let ndk_root = toolchains_dir.parent()?;
            if ndk_root.join("toolchains/llvm/prebuilt").is_dir() {
                return Some(ndk_root.to_path_buf());
            }
        }
    }

    None
}

fn detect_ndk_root() -> Option<PathBuf> {
    if let Ok(android_home) = env::var("ANDROID_HOME").or_else(|_| env::var("ANDROID_SDK_ROOT")) {
        let preferred = Path::new(&android_home).join("ndk").join("29.0.14206865");
        if preferred.join("toolchains/llvm/prebuilt").is_dir() {
            return Some(preferred);
        }
    }

    for key in ["ANDROID_NDK_ROOT", "ANDROID_NDK_HOME"] {
        if let Ok(value) = env::var(key) {
            let path = PathBuf::from(value);
            if path.join("toolchains/llvm/prebuilt").is_dir() {
                return Some(path);
            }
        }
    }

    if let Ok(android_home) = env::var("ANDROID_HOME").or_else(|_| env::var("ANDROID_SDK_ROOT")) {
        let ndk_dir = Path::new(&android_home).join("ndk");
        if let Ok(entries) = std::fs::read_dir(ndk_dir) {
            let mut versions: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|v| v.path())).collect();
            versions.sort();
            versions.reverse();
            if let Some(path) = versions
                .into_iter()
                .find(|p| p.join("toolchains/llvm/prebuilt").is_dir())
            {
                return Some(path);
            }
        }
    }

    None
}

fn detect_host_tag(ndk_root: &Path) -> Option<&'static str> {
    ["windows-x86_64", "linux-x86_64", "darwin-x86_64", "darwin-arm64"]
        .into_iter()
        .find(|tag| ndk_root.join("toolchains/llvm/prebuilt").join(tag).is_dir())
}

fn detect_ninja_from_sdk(ndk_root: &Path) -> Option<PathBuf> {
    let sdk_root = ndk_root.parent()?.parent()?;
    let cmake_root = sdk_root.join("cmake");
    let mut candidates = std::fs::read_dir(cmake_root)
        .ok()?
        .filter_map(|e| e.ok().map(|v| v.path()))
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.reverse();

    candidates
        .into_iter()
        .map(|dir| dir.join("bin").join(if cfg!(windows) { "ninja.exe" } else { "ninja" }))
        .find(|path| path.is_file())
}

fn detect_cmake_from_sdk(ndk_root: &Path) -> Option<PathBuf> {
    let sdk_root = ndk_root.parent()?.parent()?;
    let preferred = sdk_root.join("cmake").join("3.31.6").join("bin").join(if cfg!(windows) {
        "cmake.exe"
    } else {
        "cmake"
    });
    if preferred.is_file() {
        return Some(preferred);
    }

    let cmake_root = sdk_root.join("cmake");
    let mut candidates = std::fs::read_dir(cmake_root)
        .ok()?
        .filter_map(|e| e.ok().map(|v| v.path()))
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.reverse();

    candidates
        .into_iter()
        .map(|dir| dir.join("bin").join(if cfg!(windows) { "cmake.exe" } else { "cmake" }))
        .find(|path| path.is_file())
}

fn android_abi(target: &str) -> Option<&'static str> {
    match target {
        "aarch64-linux-android" => Some("arm64-v8a"),
        "armv7-linux-androideabi" => Some("armeabi-v7a"),
        "i686-linux-android" => Some("x86"),
        "x86_64-linux-android" => Some("x86_64"),
        _ => None,
    }
}

fn apply_bindgen_env(mut builder: bindgen::Builder) -> bindgen::Builder {
    let target = env::var("TARGET").unwrap_or_default();
    let normalized = target.replace('-', "_");

    for key in [
        format!("BINDGEN_EXTRA_CLANG_ARGS_{}", normalized),
        "BINDGEN_EXTRA_CLANG_ARGS".to_string(),
    ] {
        if let Ok(extra) = env::var(&key) {
            builder = append_clang_args(builder, &extra);
        }
    }

    if target.contains("android") {
        let ndk_root = detect_ndk_root().or_else(|| detect_ndk_from_cc(&target));
        if let Some(ndk_root) = ndk_root {
            if let Some(host_tag) = detect_host_tag(&ndk_root) {
                let sysroot = ndk_root.join("toolchains/llvm/prebuilt").join(host_tag).join("sysroot");
                if sysroot.is_dir() {
                    builder = builder.clang_arg(format!("--sysroot={}", sysroot.display()));
                    if let Some(triple) = android_target_triple(&target) {
                        let target_include = sysroot.join("usr").join("include").join(triple);
                        if target_include.is_dir() {
                            builder = builder.clang_arg(format!("-I{}", target_include.display()));
                        }
                    }
                    builder = builder.clang_arg("-DANDROID");
                }
            }
        }
    }

    builder
}

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let src_path = PathBuf::from(&manifest_dir).join("src");
    let target = env::var("TARGET").unwrap_or_default();

    cc::Build::new()
        .file(src_path.join("hook_engine.c"))
        .file(src_path.join("hook_engine_mem.c"))
        .file(src_path.join("hook_engine_inline.c"))
        .file(src_path.join("hook_engine_redir.c"))
        .file(src_path.join("hook_engine_art.c"))
        .file(src_path.join("hook_engine_oat_patch.c"))
        .file(src_path.join("arm64_writer.c"))
        .file(src_path.join("arm64_relocator.c"))
        .file(src_path.join("recomp/recomp_page.c"))
        .include(&src_path)
        .include(src_path.join("recomp"))
        .opt_level(2)
        .flag("-fPIC")
        .flag("-fno-exceptions")
        .warnings(false)
        .compile("hook_engine");

    let lsplant_src = PathBuf::from(&manifest_dir).join("native/lsplant_core");
    let mut lsplant_cfg = cmake::Config::new(&lsplant_src);
    lsplant_cfg.profile("Release");

    if target.contains("android") {
        let ndk_root = detect_ndk_root()
            .or_else(|| detect_ndk_from_cc(&target))
            .expect("Android NDK root not found for LSPlant CMake build");
        let cmake_bin = detect_cmake_from_sdk(&ndk_root).expect("CMake not found in Android SDK packages");
        let toolchain = ndk_root.join("build").join("cmake").join("android.toolchain.cmake");
        let ninja = detect_ninja_from_sdk(&ndk_root).expect("Ninja not found in Android SDK CMake packages");
        let abi = android_abi(&target).expect("Unsupported Android target ABI");
        let api = "21";

        lsplant_cfg
            .generator("Ninja")
            .define("CMAKE_SYSTEM_NAME", "Android")
            .define("CMAKE_EXPORT_COMPILE_COMMANDS", "ON")
            .define("CMAKE_SYSTEM_VERSION", api)
            .define("CMAKE_TOOLCHAIN_FILE", toolchain)
            .define("CMAKE_MAKE_PROGRAM", ninja)
            .define("ANDROID_NDK", &ndk_root)
            .define("CMAKE_ANDROID_NDK", &ndk_root)
            .define("ANDROID_ABI", abi)
            .define("CMAKE_ANDROID_ARCH_ABI", abi)
            .define("ANDROID_PLATFORM", format!("android-{api}"))
            .define("ANDROID_STL", "c++_static")
            .define("ANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES", "ON")
            .define("ANDROID_CPP_FEATURES", "exceptions;rtti")
            .define("CMAKE_C_FLAGS", "-O3")
            .define("CMAKE_CXX_FLAGS", "-O3");

        if let Some((cxx_static, cxxabi)) = android_cxx_static_libs(&ndk_root, &target) {
            let cxx_out = out_path.join("cxx-static");
            std::fs::create_dir_all(&cxx_out).expect("failed to create cxx-static output dir");
            std::fs::copy(&cxx_static, cxx_out.join("libc++_static.a")).expect("failed to copy libc++_static.a");
            std::fs::copy(&cxxabi, cxx_out.join("libc++abi.a")).expect("failed to copy libc++abi.a");
            println!("cargo:rustc-link-search=native={}", cxx_out.display());
        }

        env::set_var("CMAKE", cmake_bin);
    }

    let lsplant_dst = lsplant_cfg.build();
    let lsplant_build = lsplant_dst.join("build");
    println!("cargo:rustc-link-search=native={}", lsplant_dst.join("lib").display());
    println!("cargo:rustc-link-search=native={}", lsplant_build.display());
    println!(
        "cargo:rustc-link-search=native={}",
        lsplant_build.join("external").join("aliuhook").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        lsplant_build.join("external").join("dex_builder").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        lsplant_build.join("dobby").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        lsplant_build
            .join("dobby")
            .join("builtin-plugin")
            .join("SymbolResolver")
            .display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        lsplant_build
            .join("dobby")
            .join("external")
            .join("logging")
            .display()
    );

    let quickjs_src = PathBuf::from(&manifest_dir).join("quickjs-src");
    let quickjs_c = quickjs_src.join("quickjs.c");
    let quickjs_h = quickjs_src.join("quickjs.h");
    if quickjs_c.exists() && quickjs_h.exists() {
        let quickjs_version = std::fs::read_to_string(quickjs_src.join("VERSION"))
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".to_owned());
        let has_libbf = quickjs_src.join("libbf.c").exists();

        let mut build = cc::Build::new();
        build
            .file(&quickjs_c)
            .file(quickjs_src.join("dtoa.c"))
            .file(quickjs_src.join("libregexp.c"))
            .file(quickjs_src.join("libunicode.c"))
            .file(quickjs_src.join("cutils.c"))
            .file(src_path.join("quickjs_wrapper.c"))
            .include(&quickjs_src)
            .include(&src_path)
            .opt_level(2)
            .flag("-fPIC")
            .flag("-fno-exceptions")
            .flag(&format!("-DCONFIG_VERSION=\"{}\"", quickjs_version))
            .flag("-D_GNU_SOURCE")
            .flag_if_supported("-Wno-implicit-const-int-float-conversion")
            .warnings(false);

        if has_libbf {
            build.file(quickjs_src.join("libbf.c"));
            build.flag("-DCONFIG_BIGNUM");
        }

        if target.contains("android") {
            build.flag("-DANDROID");
        }

        build.compile("quickjs");

        let bindings = apply_bindgen_env(bindgen::Builder::default())
            .header(quickjs_src.join("quickjs.h").to_string_lossy().to_string())
            .header(src_path.join("quickjs_wrapper.h").to_string_lossy().to_string())
            .clang_arg(format!("-I{}", quickjs_src.display()))
            .clang_arg(format!("-I{}", src_path.display()))
            .clang_arg("-xc")
            .generate_comments(true)
            .derive_debug(true)
            .derive_default(true)
            .layout_tests(false)
            .allowlist_function("JS_.*")
            .allowlist_function("js_.*")
            .allowlist_function("__JS_.*")
            .allowlist_function("qjs_.*")
            .allowlist_type("JS.*")
            .allowlist_var("JS_.*")
            .use_core()
            .generate()
            .expect("Unable to generate QuickJS bindings");

        bindings
            .write_to_file(out_path.join("quickjs_bindings.rs"))
            .expect("Couldn't write QuickJS bindings!");

        println!("cargo:rustc-link-lib=static=quickjs");
    } else {
        std::fs::write(
            out_path.join("quickjs_bindings.rs"),
            "// QuickJS source not found - run setup script to download\n",
        )
        .expect("Failed to write placeholder bindings");

        println!("cargo:warning=QuickJS source not initialized at {:?}", quickjs_src);
        println!("cargo:warning=Run: git submodule update --init --recursive quickjs-hook/quickjs-src");
        println!("cargo:warning=Or run: cd quickjs-hook && ./setup_quickjs.sh");
    }

    let hook_bindings = apply_bindgen_env(bindgen::Builder::default())
        .header(src_path.join("hook_engine.h").to_string_lossy().to_string())
        .header(src_path.join("arm64_writer.h").to_string_lossy().to_string())
        .header(src_path.join("arm64_relocator.h").to_string_lossy().to_string())
        .header(src_path.join("recomp/recomp_page.h").to_string_lossy().to_string())
        .clang_arg(format!("-I{}", src_path.display()))
        .clang_arg("-xc")
        .generate_comments(true)
        .derive_debug(true)
        .derive_default(true)
        .layout_tests(false)
        .allowlist_function("hook_.*")
        .allowlist_function("arm64_writer_.*")
        .allowlist_function("arm64_relocator_.*")
        .allowlist_function("recompile_page")
        .allowlist_function("resolve_art_trampoline")
        .allowlist_type("Hook.*")
        .allowlist_type("Arm64.*")
        .allowlist_type("RecompileStats")
        .allowlist_var("ARM64_.*")
        .allowlist_var("RECOMP_.*")
        .use_core()
        .generate()
        .expect("Unable to generate hook_engine bindings");

    hook_bindings
        .write_to_file(out_path.join("hook_bindings.rs"))
        .expect("Couldn't write hook_engine bindings!");

    println!("cargo:rustc-link-lib=static=hook_engine");
    println!("cargo:rustc-link-lib=static=rf_lsplant");
    println!("cargo:rustc-link-lib=static=aliuhook");
    println!("cargo:rustc-link-lib=static=dex_builder_static");
    println!("cargo:rustc-link-lib=static=dobby");
    println!("cargo:rustc-link-lib=static=symbol_resolver");
    println!("cargo:rustc-link-lib=static=logging");
    println!("cargo:rustc-link-lib=static=c++_static");
    println!("cargo:rustc-link-lib=static=c++abi");
    println!("cargo:rerun-if-changed=src/hook_engine.c");
    println!("cargo:rerun-if-changed=src/hook_engine.h");
    println!("cargo:rerun-if-changed=src/hook_engine_internal.h");
    println!("cargo:rerun-if-changed=src/hook_engine_mem.c");
    println!("cargo:rerun-if-changed=src/hook_engine_inline.c");
    println!("cargo:rerun-if-changed=src/hook_engine_redir.c");
    println!("cargo:rerun-if-changed=src/hook_engine_art.c");
    println!("cargo:rerun-if-changed=src/hook_engine_oat_patch.c");
    println!("cargo:rerun-if-changed=src/arm64_writer.c");
    println!("cargo:rerun-if-changed=src/arm64_writer.h");
    println!("cargo:rerun-if-changed=src/arm64_relocator.c");
    println!("cargo:rerun-if-changed=src/arm64_relocator.h");
    println!("cargo:rerun-if-changed=src/recomp/recomp_page.c");
    println!("cargo:rerun-if-changed=src/recomp/recomp_page.h");
    println!("cargo:rerun-if-changed=quickjs-src/VERSION");
    println!("cargo:rerun-if-changed=quickjs-src/quickjs.c");
    println!("cargo:rerun-if-changed=quickjs-src/quickjs.h");
    println!("cargo:rerun-if-changed=quickjs-src/dtoa.c");
    println!("cargo:rerun-if-changed=quickjs-src/libregexp.c");
    println!("cargo:rerun-if-changed=quickjs-src/libunicode.c");
    println!("cargo:rerun-if-changed=quickjs-src/cutils.c");
    println!("cargo:rerun-if-changed=quickjs-src/libbf.c");
    println!("cargo:rerun-if-changed=src/quickjs_wrapper.c");
    println!("cargo:rerun-if-changed=src/quickjs_wrapper.h");
    println!("cargo:rerun-if-changed=native/lsplant_core");
    println!("cargo:rerun-if-changed=native/lsplant_core/include");
    println!("cargo:rerun-if-changed=native/lsplant_core/src");
    println!("cargo:rerun-if-changed=native/lsplant_core/CMakeLists.txt");
    println!("cargo:rerun-if-changed=build.rs");
}
