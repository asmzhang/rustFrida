@echo off
REM Build script for rust_frida eBPF uprobe (Windows CMD)
REM
REM This script compiles the eBPF program and copies it to the parent directory
REM for easy loading by the user-space program.

setlocal enabledelayedexpansion

cd /d "%~dp0"

echo [*] Building rust_frida eBPF uprobe...

REM Check if rust-lld (part of bpf-linker) is available
where rust-lld >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [!] bpf-linker not found. Installing...
    cargo install bpf-linker
    if !ERRORLEVEL! neq 0 (
        echo [!] Failed to install bpf-linker
        exit /b 1
    )
)

REM Check if target is added
echo [*] Checking for bpfel-unknown-none target...
rustup target list | findstr /C:"bpfel-unknown-none (installed)" >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [*] Adding bpfel-unknown-none target...
    rustup target add bpfel-unknown-none
    if !ERRORLEVEL! neq 0 (
        echo [!] Failed to add target
        exit /b 1
    )
)

REM Build the eBPF program
echo [*] Compiling eBPF program...
cargo build --target bpfel-unknown-none --release
if %ERRORLEVEL% neq 0 (
    echo [!] Build failed
    exit /b 1
)

REM Copy to parent directory
set "OUTPUT_FILE=target\bpfel-unknown-none\release\dlopen_probe"
set "DEST_FILE=..\dlopen_probe.o"

if exist "%OUTPUT_FILE%" (
    copy /Y "%OUTPUT_FILE%" "%DEST_FILE%" >nul
    echo [+] eBPF program built successfully!
    echo [+] Output: %DEST_FILE%

    REM Show file size
    for %%A in ("%DEST_FILE%") do (
        echo [+] Size: %%~zA bytes
    )
) else (
    echo [!] Build failed - output file not found
    exit /b 1
)

echo [*] Build complete!
endlocal