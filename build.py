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


def autodetect_libclang():
    if sys.platform != "win32" or os.environ.get("LIBCLANG_PATH"):
        return

    ndk_base = None
    for env_key in ["ANDROID_NDK_ROOT", "ANDROID_NDK_HOME", "ANDROID_NDK"]:
        env_value = os.environ.get(env_key)
        if env_value:
            ndk_base = Path(env_value).expanduser().parent
            if ndk_base.name == "ndk":
                break

    if not ndk_base or not ndk_base.is_dir():
        for sdk_key in ["ANDROID_HOME", "ANDROID_SDK_ROOT", "ANDROID_SDK"]:
            env_value = os.environ.get(sdk_key)
            if env_value:
                ndk_base = Path(env_value).expanduser() / "ndk"
                if ndk_base.is_dir():
                    break

    if not ndk_base or not ndk_base.is_dir():
        print("[!] Warning: Could not find NDK directory for LIBCLANG_PATH auto-detection.")
        return

    for ndk_ver in sorted(ndk_base.iterdir(), reverse=True):
        if not ndk_ver.is_dir():
            continue
        clang_path = ndk_ver / "toolchains" / "llvm" / "prebuilt" / "windows-x86_64" / "bin"
        if (clang_path / "libclang.dll").exists():
            os.environ["LIBCLANG_PATH"] = str(clang_path)
            print(f"[!] Auto-detected LIBCLANG_PATH: {clang_path}")
            return

    print("[!] Warning: Could not find libclang.dll in any NDK; bindgen may fail.")


def main():
    print("=== rustFrida Automated Build Pipeline ===")

    setup_script = REPO_ROOT / "scripts" / "setup_cargo_config.py"
    if not setup_script.exists():
        print(f"[-] Error: Cannot find {setup_script}")
        sys.exit(1)

    print("\n[1/4] Generating Cargo configuration...")
    run_cmd([sys.executable, str(setup_script), "--force"], cwd=REPO_ROOT)

    autodetect_libclang()

    loader_script = REPO_ROOT / "loader" / "build_helpers.py"
    if not loader_script.exists():
        print(f"[-] Error: Cannot find {loader_script}")
        sys.exit(1)

    print("\n[2/4] Building loader shellcode...")
    run_cmd([sys.executable, str(loader_script)], cwd=REPO_ROOT / "loader")

    print("\n[3/4] Building agent...")
    run_cmd(["cargo", "build", "-p", "agent", "--release", "--target", "aarch64-linux-android"], cwd=REPO_ROOT)

    print("\n[4/4] Building rust_frida...")
    run_cmd(["cargo", "build", "-p", "rust_frida", "--release", "--target", "aarch64-linux-android"], cwd=REPO_ROOT)

    print("\n=== Build Complete ===")
    print("Target output: target/aarch64-linux-android/release/rustfrida")


if __name__ == "__main__":
    main()
