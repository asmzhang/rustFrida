/**
 * rustFrida QBDI Trace Example
 * 
 * 演示如何使用 rustFrida 内置的 QBDI (QuarkslaB Dynamic binary Instrumentation) 引擎，
 * 对指定的 Native 函数进行细粒度指令级 Tracing 与虚拟堆栈栈调用。
 *
 * 运行方式:
 * ./rustfrida --spawn com.package.name -l qbdi_trace_example.js
 * 
 * （注意：目标应用/测试环境必须是通过带有 `--features qbdi` 编译出来的 agent 注入，才会开启对象 qbdi）
 */

// 1. 查找目标模块与基址
var targetModule = "libnative.so";
var targetSymbol = "JNI_OnLoad"; // 测试用：通常追踪 OLLVM 或者混淆程度高的核心鉴权函数

// 很多时候我们需要延迟等 SO 加载完成。如果在 Spawn 模式，建议搭配 setInterval
var checkInterval = setInterval(function() {
    var base = Module.findBaseAddress(targetModule);
    if (!base) {
        return; // 等待 SO 加载
    }
    clearInterval(checkInterval);

    console.log("[*] Target Module " + targetModule + " loaded at: " + base);

    // 尝试寻找我们要模拟调用的鉴权/算法函数地址
    var targetAddress = Module.findExportByName(targetModule, targetSymbol);
    if (!targetAddress) {
        console.error("[-] 无法找到符号: " + targetSymbol);
        return;
    }

    console.log("[*] Found target function at: " + targetAddress);

    // ==========================================
    // 开始构建 QBDI VM 与上下文
    // ==========================================
    console.log("[+] Initializing QBDI VM...");
    var vm = qbdi.newVM();
    if (!vm) {
        console.error("[-] QBDI VM 创建失败!");
        return;
    }

    // 声明指令监控范围：将整个目标 SO 加入 Instrument 范围
    // 只有范围内的指令执行才会被 Trace 捕获（可以避免调跑到 libc 产生天量日志）
    if (!qbdi.addInstrumentedModuleFromAddr(vm, base)) {
        console.error("[-] 无法挂载需要监控的模块范围!");
        qbdi.destroyVM(vm);
        return;
    }

    // 为模拟环境开辟独立的虚拟堆栈空间 (大小: 1MB = 0x100000)
    qbdi.allocateVirtualStack(vm, 0x100000);

    // 注册指令集回调侦听
    // 第三个参数可选: 为空则默认以 Protobuf 格式抓取到 /data/data/<package>/trace_bundle.pb
    console.log("[+] Registering Trace Callbacks...");
    qbdi.registerTraceCallbacks(vm, targetAddress, null);

    // ==========================================
    // 执行模拟调用 (Simulate Call)
    // ==========================================
    // 假设被调用的函数原型是： void* auth_check(void* arg0, int arg1)
    var arg0 = ptr("0x0"); // 传个假指针
    var arg1 = 1234;       // 参数 2

    console.log("[+] Simulating function execution...");
    // 预配置参数到寄存器 x0, x1 等等...
    qbdi.simulateCall(vm, ptr("0x0"), arg0, arg1); // 第二个参数是 retAddr，填 0 即可

    // 驱动 QBDI 引擎执行一直到 return 结束
    var runSuccess = qbdi.run(vm, targetAddress, ptr("0x0"));
    if (!runSuccess) {
        console.error("[-] QBDI VM 执行中途奔溃或失败。Error: " + qbdi.lastError());
    } else {
        console.log("[+] QBDI Simulation completed successfully!");
    }

    // 提取结果：获取虚拟 CPU 跑完后的寄存器快照 (X0 为默认返回值)
    var resultX0 = qbdi.getGPR(vm, qbdi.REG_RETURN);
    console.log("[*] Function returned: " + resultX0);

    // ==========================================
    // 清理资源
    // ==========================================
    console.log("[+] Unregistering & Destroying VM...");
    qbdi.unregisterTraceCallbacks(vm);
    qbdi.destroyVM(vm);

    console.log("[*] Trace 日志已经成功捕获！");
    console.log("    请在 IDA 中配合 qbdi-replay 插件导入生成的 trace_bundle.pb 进行时光倒流/指令重放分析。");
}, 500);
