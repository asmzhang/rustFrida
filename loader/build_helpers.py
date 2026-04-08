#!/usr/bin/env python3
"""
build_helpers.py - Compile Frida-style bootstrapper + loader into binary shellcode.

Produces:
  build/bootstrapper.bin - Process probing + libc API resolution shellcode
  build/rustfrida-loader.bin - Agent loading + IPC handshake shellcode

Both are position-independent ARM64 binary blobs extracted from the .payload
section using the helper.lds linker script.
"""

import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
HELPERS_DIR = os.path.join(SCRIPT_DIR, "helpers")
BUILD_DIR = os.path.join(SCRIPT_DIR, "build")


def find_ndk():
    """Find the latest Android NDK using env variables."""
    candidates = []

    for env_name in ("ANDROID_NDK_ROOT", "ANDROID_NDK_HOME"):
        env_value = os.environ.get(env_name)
        if env_value:
            env_value = os.path.normpath(env_value)
            parent_dir = os.path.dirname(env_value)
            if os.path.basename(parent_dir) == "ndk" and os.path.isdir(parent_dir):
                versions = sorted(
                    [d for d in os.listdir(parent_dir) if os.path.isdir(os.path.join(parent_dir, d))],
                    reverse=True,
                )
                ndk_25 = [v for v in versions if "25." in v]
                candidates.extend(os.path.join(parent_dir, v) for v in ndk_25)
            candidates.append(env_value)

    android_home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if android_home:
        ndk_dir = os.path.join(os.path.normpath(android_home), "ndk")
        if os.path.isdir(ndk_dir):
            versions = sorted(
                [d for d in os.listdir(ndk_dir) if os.path.isdir(os.path.join(ndk_dir, d))],
                reverse=True,
            )
            ndk_25 = [v for v in versions if "25." in v]
            others = [v for v in versions if "25." not in v]
            candidates.extend(os.path.join(ndk_dir, v) for v in ndk_25 + others)

    for default_ndk_dir in [
        os.path.expanduser("~/Android/Sdk/ndk"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk", "ndk"),
        "/opt/android-sdk/ndk",
    ]:
        if default_ndk_dir and os.path.isdir(default_ndk_dir):
            versions = sorted(
                [d for d in os.listdir(default_ndk_dir) if os.path.isdir(os.path.join(default_ndk_dir, d))],
                reverse=True,
            )
            ndk_25 = [v for v in versions if "25." in v]
            others = [v for v in versions if "25." not in v]
            candidates.extend(os.path.join(default_ndk_dir, v) for v in ndk_25 + others)

    for candidate in candidates:
        if os.path.isdir(os.path.join(candidate, "toolchains", "llvm", "prebuilt")):
            return candidate

    print("错误: 未能找到 Android NDK。请设置 ANDROID_NDK_HOME/ANDROID_HOME，或安装到常见默认路径。")
    sys.exit(1)


def find_tool(ndk_path, tool):
    """Find an NDK tool in the toolchain."""
    for host in ["windows-x86_64", "linux-x86_64", "darwin-x86_64", "darwin-arm64"]:
        toolchain = os.path.join(ndk_path, "toolchains", "llvm", "prebuilt", host, "bin")
        if not os.path.isdir(toolchain):
            continue
        exe_ext = ".exe" if "windows" in host else ""
        llvm_tool = os.path.join(toolchain, f"llvm-{tool}{exe_ext}")
        if os.path.isfile(llvm_tool):
            return llvm_tool
        aarch64_tool = os.path.join(toolchain, f"aarch64-linux-android-{tool}{exe_ext}")
        if os.path.isfile(aarch64_tool):
            return aarch64_tool
    return None


def find_clang(ndk_path, api=33):
    """Find the NDK clang for aarch64."""
    for host in ["windows-x86_64", "linux-x86_64", "darwin-x86_64", "darwin-arm64"]:
        toolchain = os.path.join(ndk_path, "toolchains", "llvm", "prebuilt", host, "bin")
        if not os.path.isdir(toolchain):
            continue
        exe_ext = ".cmd" if "windows" in host else ""
        clang = os.path.join(toolchain, f"aarch64-linux-android{api}-clang{exe_ext}")
        if os.path.isfile(clang):
            return clang
        clang = os.path.join(toolchain, f"clang{exe_ext}")
        if os.path.isfile(clang):
            return clang
    return None


def run_cmd(cmd, desc=""):
    """Run a command and check for errors."""
    if desc:
        print(f"  {desc}")
    print(f"    $ {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  错误: 命令失败 (exit {result.returncode})")
        if result.stderr:
            print(f"  stderr: {result.stderr}")
        if result.stdout:
            print(f"  stdout: {result.stdout}")
        sys.exit(1)
    return result


def build_shellcode(cc, ld, objcopy, sources, output_name, extra_cflags=None):
    """Compile C sources into a binary shellcode blob."""
    if extra_cflags is None:
        extra_cflags = []

    lds = os.path.join(HELPERS_DIR, "helper.lds")
    obj_files = []

    cflags = [
        "-target",
        "aarch64-linux-android33",
        "-fPIC",
        "-fno-stack-protector",
        "-fvisibility=hidden",
        "-fno-function-sections",
        "-fno-data-sections",
        "-fno-asynchronous-unwind-tables",
        "-fomit-frame-pointer",
        "-O2",
        "-Wall",
        f"-I{HELPERS_DIR}",
    ] + extra_cflags

    ldflags = [
        "-target",
        "aarch64-linux-android33",
        "-nostdlib",
        "-shared",
        f"-Wl,-T,{lds}",
        "-Wl,--no-undefined",
    ]

    for src in sources:
        src_path = os.path.join(HELPERS_DIR, src)
        obj_path = os.path.join(BUILD_DIR, os.path.splitext(src)[0] + ".o")
        obj_files.append(obj_path)
        run_cmd([cc] + cflags + ["-c", src_path, "-o", obj_path], f"编译 {src}")

    so_path = os.path.join(BUILD_DIR, output_name + ".so")
    run_cmd([ld] + ldflags + obj_files + ["-o", so_path], f"链接 {output_name}.so")

    bin_path = os.path.join(BUILD_DIR, output_name + ".bin")
    run_cmd(
        [objcopy, "-O", "binary", "--only-section=.payload", so_path, bin_path],
        f"提取 {output_name}.bin",
    )

    size = os.path.getsize(bin_path)
    print(f"  [ok] {output_name}.bin: {size} bytes")
    return bin_path


def main():
    print("=== 构建 Frida-style helpers ===\n")

    ndk = find_ndk()
    print(f"NDK: {ndk}")

    cc = find_clang(ndk)
    if not cc:
        print("错误: 未找到 clang")
        sys.exit(1)

    ld = cc

    objcopy = find_tool(ndk, "objcopy")
    if not objcopy:
        print("错误: 未找到 objcopy")
        sys.exit(1)

    print(f"CC: {cc}")
    print(f"OBJCOPY: {objcopy}")
    print()

    os.makedirs(BUILD_DIR, exist_ok=True)

    print("[1/2] 构建 bootstrapper...")
    build_shellcode(
        cc,
        ld,
        objcopy,
        sources=["bootstrapper.c", "elf-parser.c"],
        output_name="bootstrapper",
        extra_cflags=[
            "-DNOLIBC",
            "-DNOLIBC_DISABLE_START",
            "-DNOLIBC_IGNORE_ERRNO",
            "-ffreestanding",
        ],
    )
    print()

    print("[2/2] 构建 rustfrida-loader...")
    build_shellcode(
        cc,
        ld,
        objcopy,
        sources=["rustfrida-loader.c", "syscall.c"],
        output_name="rustfrida-loader",
        extra_cflags=["-ffreestanding"],
    )
    print()

    print("=== 构建完成 ===")
    print(f"  bootstrapper.bin:      {BUILD_DIR}/bootstrapper.bin")
    print(f"  rustfrida-loader.bin:  {BUILD_DIR}/rustfrida-loader.bin")


if __name__ == "__main__":
    main()
