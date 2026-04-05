import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

def run_cmd(cmd, cwd=None):
    print(f"\n=> Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd)
    if result.returncode != 0:
        print(f"[-] Command failed with exit code {result.returncode}: {' '.join(cmd)}")
        sys.exit(result.returncode)

def main():
    print("=== rustFrida Automated Build Pipeline ===")
    
    # Step 1: Detect NDK and generate .cargo/config.toml
    setup_script = REPO_ROOT / "scripts" / "setup_cargo_config.py"
    if not setup_script.exists():
        print(f"[-] Error: Cannot find {setup_script}")
        sys.exit(1)
        
    print("\n[1/4] Generating dynamic Cargo configuration...")
    # Use the same python executable that invoked this script
    run_cmd([sys.executable, str(setup_script), "--force"])

    # Auto-detect LIBCLANG_PATH for bindgen on Windows
    if sys.platform == "win32" and not os.environ.get("LIBCLANG_PATH"):
        ndk_base = None
        for env_key in ["ANDROID_NDK_ROOT", "ANDROID_NDK_HOME", "ANDROID_NDK"]:
            if os.environ.get(env_key):
                ndk_base = Path(os.environ[env_key]).expanduser().parent
                if ndk_base.name == "ndk": break
        
        if not ndk_base or not ndk_base.is_dir():
            sdks = ["ANDROID_HOME", "ANDROID_SDK_ROOT", "ANDROID_SDK"]
            for sdk in sdks:
                val = os.environ.get(sdk)
                if val:
                    ndk_base = Path(val) / "ndk"
                    if ndk_base.is_dir(): break

        found_libclang = False
        if ndk_base and ndk_base.is_dir():
            # Sort versions descending to pick the newest LLVM for parsing headers
            for ndk_ver in sorted(ndk_base.iterdir(), reverse=True):
                if not ndk_ver.is_dir(): continue
                clang_path = ndk_ver / "toolchains" / "llvm" / "prebuilt" / "windows-x86_64" / "bin"
                if (clang_path / "libclang.dll").exists():
                    os.environ["LIBCLANG_PATH"] = str(clang_path)
                    print(f"[!] Auto-detected LIBCLANG_PATH mapping to: {clang_path}")
                    found_libclang = True
                    break
        if not found_libclang:
            print("[!] Warning: Could not find libclang.dll in any NDK! bindgen (agent) may fail.")

    # Step 2: Build Bootstrapper & Loader binary shellcode
    loader_script = REPO_ROOT / "loader" / "build_helpers.py"
    if not loader_script.exists():
        print(f"[-] Error: Cannot find {loader_script}")
        sys.exit(1)

    print("\n[2/4] Building loader and bootstrapper shellcode...")
    run_cmd([sys.executable, str(loader_script)], cwd=REPO_ROOT / "loader")

    # Step 3: Compile Agent
    print("\n[3/4] Compiling rustFrida Agent (.so)...")
    run_cmd(["cargo", "build", "-p", "agent", "--release", "--target", "aarch64-linux-android"], cwd=REPO_ROOT)

    # Step 4: Compile Host CLI Integrator
    print("\n[4/4] Compiling rust_frida CLI Host...")
    run_cmd(["cargo", "build", "-p", "rust_frida", "--release", "--target", "aarch64-linux-android"], cwd=REPO_ROOT)

    print("\n=== Build Complete ===")
    print("Target output: target/aarch64-linux-android/release/rustfrida")

if __name__ == "__main__":
    main()
