// Java Hook 示例脚本

// 注意：Spawn 模式下刚启动时 App 的 ClassLoader 尚未就绪，
// 所有的 Java Hook 操作**必须**包裹在 Java.ready 回调内执行！
Java.ready(function() {
    console.log("[*] Java classloader is ready, starting hooks...");

    // 1. Hook 实例方法 (如 Activity 的生命周期函数)
    var Activity = Java.use("android.app.Activity");
    Activity.onResume.impl = function(ctx) {
        // ctx.thisObj 指向所在实例对象
        console.log("[*] Activity onResume called for:", ctx.thisObj.$className);
        return ctx.orig(); // 调用原始实现
    };

    // 2. 拦截构造函数 ($init) 的调用
    var FileClass = Java.use("java.io.File");
    FileClass.$init.overload("java.lang.String").impl = function(ctx) {
        var path = ctx.args[0];
        console.log("[*] new java.io.File(\"" + path + "\") created.");
        return ctx.orig();
    };

    console.log("[*] java_hook_example.js hooks applied successfully.");
});
