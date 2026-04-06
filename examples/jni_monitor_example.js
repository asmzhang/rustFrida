// JNI 监控示例 (监控 RegisterNatives)

// 获取 RegisterNatives 方法的地址
var registerNativesAddr = Jni.addr("RegisterNatives");

hook(registerNativesAddr, function(ctx) {
    // RegisterNatives 签名:
    // jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods);
    var env = ctx.x0;
    var clazz = ctx.x1;
    var methodsPtr = ctx.x2;
    var count = Number(ctx.x3);

    // 获取正在注册的类名
    var className = Jni.helper.env.getClassName(clazz);
    console.log("[*] RegisterNatives called for class: " + className + " (" + count + " methods)");

    // 解析 JNINativeMethod 结构体数组
    var methods = Jni.helper.structs.JNINativeMethod.readArray(ptr(methodsPtr), count);
    
    for (var i = 0; i < methods.length; i++) {
        var m = methods[i];
        // 查找该函数指针属于哪个 SO
        var mod = Module.findByAddress(m.fnPtr);
        var offset = mod ? ("+" + m.fnPtr.sub(mod.base).toString(16)) : "";
        var modName = mod ? mod.name : "unknown";
        
        console.log("  -> " + m.name + " " + m.sig + " => " + modName + offset + " (" + m.fnPtr + ")");
    }

    return ctx.orig();
}, 1); // 使用 stealth mode = 1 防止特征检测

console.log("[*] JNI monitor loaded.");
