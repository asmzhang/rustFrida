# SukiSU 内核编译与 KPM (KernelPatch) 部署指南

本指南旨在为需要在 Android 设备上部署 KernelPatch (KPM) 模块的开发者提供系统性的参考。文中总结了使用 `GKI_KernelSU_SUSFS` 编译 SukiSU 内核时的核心机制、已知冲突陷阱以及最佳部署实践。

---

## 1. 为什么选择 SukiSU 内核？
目前主流的官方内核级挂载工具（如标准 KernelSU 或 KernelSU-Next）主要提供模块（Magisk Module）加载支持环境，原生并未直接暴露或预集成 KernelPatch (KPM) 基础设施。
`SukiSU` 作为专注于高阶底层的派生分支，其核心优势在源码层级融合了 KernelPatch。因此，若需要直接注入并挂载自行编写的 `.kpm` 格式的监控或系统挂钩程序，配置并刷入 SukiSU 内核是前置必要条件。

## 2. 关于 GKI 内核编译分支的选择 (严重陷阱)
如果使用开源云编译框架（如 `GKI_KernelSU_SUSFS`）进行 SukiSU 交叉编译，请务必谨慎选择源码分支。

* **不推荐的分支：`Dev(开发版 / builtin)`**
  在结合 SUSFS 隐藏特性时，SukiSU 的开发分支存在未解决的代码冲突。其源码中存在明确的变量宏定义重叠（例如 `ksu_handle_devpts` 符号重定义）。即便通修改脚本强制消除编译期错误，带有缺陷的补丁栈依然会在运行期产生严重问题。在 Android 13 等环境下挂载包含冲突特性的模块，将直接触发内核异常（Kernel Panic），导致设备**无限重启（Infinite Bootloop）**。

* **推荐操作：选择 `Stable(标准版)` 分支**
  在 GitHub Actions 构建流水线中，务必选择 `Stable` 分支。此分支映射经过长期验证的主线代码基线，能确保在开启 KPM 支持和 SUSFS 功能时保持内核树的系统级稳定性，避免启动死机等硬伤。

---

## 3. 内核异常导致无限重启（Bootloop）的恢复方案
若尝试刷入异常实验性内核后设备无法进入系统（Bootloop），属于软件层面的内核崩溃，可以通过恢复原始系统内核来解决：
1. 强制长按 `音量下键 + 电源键` 使设备进入 **Fastboot 模式**。
2. 提取并准备一份与设备当前系统完全匹配的原版（出厂）`boot.img`。
3. 通过主机命令线工具执行内核还原并重启：
   ```bash
   fastboot flash boot boot.img
   fastboot reboot
   ```

---

## 4. AnyKernel3 与 boot.img 的刷入说明
SukiSU 编译流水线成功后，产物通常包含两个核心分发包文件：
* **`boot.img`**
  此镜像文件代表了当前内含完整新内核的绝对覆盖包。适合设备处于 Fastboot 等工程模式需要硬性、整体性替换内核分区时使用。
* **`AnyKernel3.zip`（AK3 包）**
  **（推荐更新途径）** AK3 包利用了动态解包与重新打包技术。能够在刷入时保留设备原有的、可能包含重要厂家驱动的 Ramdisk（根文件系统层）并仅热替换底层 Kernel 二进制。推荐在系统正常时通过 `Kernelflasher`、或 Recovery 等手段进行无损化更新。

---

## 5. KernelPatch (KPM) 模块挂载与部署方案
将编译出来的 `.kpm` 功能模块移入设备后，需要特定的环境和流程才能挂载，图形化管理器（SukiSU App）不接受裸二进制文件的直接安装。

* **途径 A：CLI 命令行挂载（开发测试用）**
  无需打包，直接使用具有 KPM 特性的底座管理守护进程（ksud）加载模块：
  ```bash
  adb shell su -c "/data/adb/ksud kpm load /sdcard/您编译模块的绝对路径.kpm"
  ```

* **途径 B：标准模块化开机自启部署（分发推荐）**
  任何模块管理器仅识别含有 `module.prop` 规格的压缩包形式系统。
  推荐利用本工程提供的 **KPM-Build-Anywhere 构建架构**，通过下述自动化部署命令进行完整打包：
  
  ```bash
  # 携带 NDK 与 KP_DIR 绝对路径进行安全全自动发版、打包
  python build.py --module my_module_name --ndk "C:\path\to\NDK" --kp-dir "../SukiSU_KernelPatch_patch"
  ```
  该架构将自动嗅探 C 语言源码、通过交叉编译工具链生成底层二进制 `.kpm`，并动态构建 `module.prop` 标识及由 `ksud` 执行守护挂载的 `service.sh`，同时将其最终规范化封装为标准的管理器直装包（如 `kpm-dlopen-monitor_v1.0.zip`）。安装此类标准模块后，系统重启即可实现自动化的底层常驻注入。

---

## 6. KPM 开发与调试核心排错 (GKI 架构兼容性)
在开发自定义 KPM Syscall 拦截器（如拦截 `__NR_openat`）时，**千万不要直接通过裸指针硬读参数**！

### 严重陷阱：GKI 内核的 Syscall Wrapper
自 Linux 4.17 (ARM64) 引入 Syscall Wrapper 以及 Android 全面推广 GKI 系列内核（Kernel >= 5.10）后，内核进入 `sys_XXX` 函数时的传参机制发生了彻底变更：
- **旧版内核 (无 Wrapper):** `args->arg0` 即引向第 0 个参数，`args->arg1` 即第 1 个参数。
- **现代 GKI 内核 (有 Wrapper):** Hook 函数接收到的实际是单一参数 `struct pt_regs *`，真实的入口参数全被封装在 `pt_regs` 结构体内部。如果此时你的代码依旧强读 `args->arg1`，抓取到的将是垃圾内存或导致空指针，直接导致拦截业务静默失败！

### 标准跨平台写法兼容
SukiSU KernelPatch 基础设施内建了兼容该层架构差异的宏，**请务必放弃使用 `args->argn` 裸指针直读，改用 `syscall_argn(args, N)` 以自动兼容不同底层架构：**

**错误写法 (拦截失败/读取乱码)：**
```c
// 极易在 GKI 设备失效！
const char __user *filename = (const char __user *)args->arg1; 
```

**推荐标准安全写法 (跨内核完美兼容)：**
```c
#include <syscall.h>

// 根据不同内核自动解包 `pt_regs` 或解析裸参数
const char __user *filename = (const char __user *)syscall_argn(args, 1);
```

### 内核态到用户态的无缝通信
部署后，请善用 `pr_info()` 结合 `dmesg` 进行日志流输出。用户态的监控应用（如 rustFrida）可以直接挂载监听 eBPF 管道或截获 `dmesg` 输出的大写预定义标签（例如 `[KPM-DLOPEN]`），快速匹配 PID、UID 与具体载入的系统路径，从而极低廉地达成内核拦截 -> 应用级处理的完整动态插桩业务闭环。
