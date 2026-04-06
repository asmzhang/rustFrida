# rustFrida

ARM64 Android 动态插桩框架。

## 环境要求

- Android NDK 25+（默认路径 `~/Android/Sdk/ndk/` 或通过环境变量配置）
- Rust toolchain + `aarch64-linux-android` target
- Python 3（用于构建流水线）
- 如果在 Windows 下且使用独立的 LLVM/Clang，必须设置环境变量（如 `$env:LIBCLANG_PATH="C:\\platform\\LLVM\\bin"`）以便 bindgen 定位 `libclang.dll`
- `.cargo/config.toml` 已配置交叉编译（由 `setup_cargo_config.py` 自动生成）

## 构建

最终产物 `rustfrida` 通过 `include_bytes!` 内嵌了 loader shellcode 和 agent SO，有严格的构建依赖顺序：
`loader shellcode` → `libagent.so` → `rustfrida (主程序)`

为了简化编译过程，项目提供了一键自动化构建脚本 `build.py`，它会自动按顺序执行所有编译步骤。

### 一键自动构建

```bash
# 如果构建出现 bindgen 找不到 libclang.dll 的错误（通常在 Windows 下），请在运行前设置：
# $env:LIBCLANG_PATH="C:\platform\LLVM\bin" (Windows PowerShell) 或者使用完整版 LLVM 路径。
$env:LIBCLANG_PATH="C:\platform\LLVM\bin"; python build.py
```

`build.py` 会依次完成以下 4 个阶段：
1. **生成 Cargo 配置**：检测和配置交叉编译规则。
2. **构建 Loader Shellcode**：预编译注入目标的裸机入口代码 (`bootstrapper.bin` + `rustfrida-loader.bin`)。
3. **构建 Agent**：编译 Hook 引擎 (`libagent.so`)。
4. **编译主程序**：内嵌上述所有壳段和模块，打包为单一的可执行文件 (`rustfrida`)。

全部完成后，您的最终注入器产出为：`target/aarch64-linux-android/release/rustfrida`。

> [!NOTE]
> 只有当您在未更改外围系统代码（如修改了单独的小组件），且不想运行全链路脚本时，才可通过 `cargo build -p agent --release --target aarch64-linux-android` 或 `cargo build -p rust_frida --release --target aarch64-linux-android` 进行局部编译。

### 可选组件（单独构建）

这些不在 default-members 里，按需构建：

**QBDI Trace 支持：** 需要先构建 qbdi-helper SO，再用 `--features qbdi` 编译 agent 和 rustfrida：

```bash
cargo build -p qbdi-helper --release           # → libqbdi_helper.so
cargo build -p agent --release --features qbdi  # agent 启用 qbdi feature
cargo build -p rust_frida --release --features qbdi  # rustfrida 嵌入 qbdi-helper SO
```

**KPM SO 加载监控（`--watch-so`）：** 传统的 eBPF 因内核版控问题现全面迁移至 KernelPatch 底层，我们提供了专属的 KPM 驱动模块。

要启动 `--watch-so`，你需要执行以下动作将拦截器模块刷入设备底层：
```bash
# 1. KPM 编译依赖 KernelPatch 驱动头文件。请将源码克隆至上一级或指定您的本地 KP_DIR：
git clone https://github.com/bmax121/KernelPatch.git ../SukiSU_KernelPatch_patch

# 2. 确保存在 NDK，进入工作目录：
cd ldmonitor-kpm

# 3. 触发自动化构建 (您也可附加 --kp-dir "/path/to/KP" 以及 --ndk "/path/to/NDK" 显式指定)
python build.py
# -> 这将在 build/ 目录下生成 "kpm-dlopen-monitor_vX.Y.zip"
```
3. 将此 `.zip` 传入手机，通过 KernelSU 等管理器安装模块。
4. 重启设备，此后附加 `--watch-so` 即可全时拦截。

## 部署 & 运行

```bash
adb push target/aarch64-linux-android/release/rustfrida /data/local/tmp/

# PID 注入
./rustfrida --pid <pid>
./rustfrida --pid <pid> -l script.js

# Spawn 模式（启动时注入）
./rustfrida --spawn com.example.app
./rustfrida --spawn com.example.app -l script.js
adb shell su -c "./rustfrida --spawn com.example.app -l script.js"

# 等待 SO 加载后注入（需提前安装上述 KPM 模块并重启生效）
./rustfrida --watch-so libnative.so

# 详细日志
./rustfrida --pid <pid> --verbose
```

### REPL 命令

```
jsinit              # 初始化 JS 引擎
jseval <expr>       # 求值表达式
loadjs <script>     # 执行脚本
jsrepl              # 交互式 REPL（Tab 补全）
exit                # 退出
```

---

## 文档与 API 参考

因单文件过长，各模块 API 参考已拆分至 [docs/api](docs/api/) 目录：

- 基础环境：[全局对象与上下文 (Globals)](docs/api/globals.md)
- 内存操作：[Memory、Module、ptr 与 Console](docs/api/builtins.md)
- C/C++ 支持：[Native Hook 与 Stealth 模式](docs/api/native_hook.md)
- Java 支持：[Java 层 Hook 与 Deopt 机制](docs/api/java_hook.md)
- JNI 支持：[JNIEnv 解析与监控](docs/api/jni_api.md)
- 动态分析：[QBDI 环境模拟与指令 Trace](docs/api/qbdi.md)

---

## 常用脚本示例 (Examples)

完整的拿来即用的脚本模板存放于 [examples](examples/) 目录下，您可以通过 `--spawn com.package.name -l script.js` 直接加载测试：

- **通用 Native Hook 模板**: [native_hook_example.js](examples/native_hook_example.js)
- **通用 Java Hook 模板**: [java_hook_example.js](examples/java_hook_example.js)
- **JNI 追踪监控模板**: [jni_monitor_example.js](examples/jni_monitor_example.js)
- **QBDI 模拟执行与 Trace 模板**: [qbdi_trace_example.js](examples/qbdi_trace_example.js)

---

## 注意事项

- **两种 hook 都建议 `return ctx.orig()`** 透传返回值
- **Native hook 改参数/返回值：** `ctx.x0 = value` 或 `ctx.orig(newArg0, newArg1)`，`return value` 覆盖返回值
- **Java hook 改参数/返回值：** `return ctx.orig(newArgs)` 改参数，`return value` 改返回值
- Spawn 模式下 Java hook 必须放在 `Java.ready(fn)` 里
- `Java.setStealth()` 必须在 `Java.use().impl` 之前调用
- `callNative()` 仅支持整数/指针参数（最多 6 个）

---

## 免责声明

本项目仅供安全研究、逆向工程学习和授权测试用途。使用者应确保在合法授权范围内使用本工具，遵守所在地区的法律法规。作者不对任何滥用、非法使用或由此造成的损失承担责任。使用本项目即表示您同意自行承担所有风险。
