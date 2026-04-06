// Native Hook 示例脚本

// 1. Hook libc 的 open 函数 (仅观测/透传)
var openPtr = Module.findExportByName("libc.so", "open");
hook(openPtr, function(ctx) {
    var path = Memory.readCString(ptr(ctx.x0));
    console.log("[*] open called with path:", path);
    // 返回原函数的执行结果（如果你不修改 ctx.x0，参数就按原样传递过去）
    return ctx.orig(); 
});

// 2. 修改函数的返回值 (模拟 getsid 或者 getuid 等返回整数的函数)
var getuidPtr = Module.findExportByName("libc.so", "getuid");
hook(getuidPtr, function(ctx) {
    var realUid = ctx.orig();
    console.log("[*] getuid called! real uid:", realUid, "spoofing to 0 (root)");
    // 修改返回值为 0 骗过调用方
    return 0; 
});

// 3. Stealth Hook 模式 (在第三个参数指定 hook 模式)
// 1 = Hook.WXSHADOW (内核 shadow 页，/proc/mem 不可见)
// 2 = Hook.RECOMP (代码页重编译，仅 4B patch)
var getpidPtr = Module.findExportByName("libc.so", "getpid");
hook(getpidPtr, function(ctx) {
    return ctx.orig();
}, 1);

console.log("[*] native_hook_example.js loaded successfully.");
