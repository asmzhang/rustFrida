# rustFrida 脚本案例库

此文件夹包含了 rustFrida 专用的 JS 脚本示例。因为 rustFrida 使用了基于 QuickJS 的自研引擎，其语法规范与传统 Frida 存在显著差异（例如以 hook 替代了 Interceptor）。以下脚本可用作实际编写或复制分析脚本时的快速参考模板。

## 案例说明

- **`native_hook_example.js`**: 包含基本的 Native C/C++ 函数 Hook（如改参数、改返回值）及伪装模式（Stealth）的演示。
- **`java_hook_example.js`**: 包含基本的 Java Hook 演示，涵盖普通方法、含重载的方法、以及构造函数 (`$init`)。
- **`jni_monitor_example.js`**: 演示如何通过 Hook JNIEnv 中的 `RegisterNatives`，动态追踪 SO 注册了哪些 JNI 函数，打印 SO 内存偏移与签名。
