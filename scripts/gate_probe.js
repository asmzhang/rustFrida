var Log = Java.use("android.util.Log");
var Activity = Java.use("android.app.Activity");
var ActivityThread = Java.use("android.app.ActivityThread");
var Application = Java.use("android.app.Application");
var LoadedApk = Java.use("android.app.LoadedApk");
var Instrumentation = Java.use("android.app.Instrumentation");

function logInfo(msg) {
    console.log("[gate_probe] " + msg);
    Log.i("RustFridaJS", msg);
}

try {
    Java.deoptimizeBootImage();
    logInfo("Java.deoptimizeBootImage() done");
} catch (e) {
    logInfo("Java.deoptimizeBootImage() failed: " + e);
}

try {
    Java.deoptimizeEverything();
    logInfo("Java.deoptimizeEverything() done");
} catch (e2) {
    logInfo("Java.deoptimizeEverything() failed: " + e2);
}

ActivityThread.handleBindApplication
    .overload("android.app.ActivityThread$AppBindData")
    .impl = function (ctx) {
        logInfo("ActivityThread.handleBindApplication entered");
        ctx.orig();
        logInfo("ActivityThread.handleBindApplication returned");
    };

LoadedApk.makeApplication
    .overload("boolean", "android.app.Instrumentation")
    .impl = function (ctx) {
        logInfo("LoadedApk.makeApplication entered");
        var app = ctx.orig();
        logInfo("LoadedApk.makeApplication returned");
        return app;
    };

Instrumentation.newApplication
    .overload("java.lang.ClassLoader", "java.lang.String", "android.content.Context")
    .impl = function (ctx) {
        logInfo("Instrumentation.newApplication entered");
        var app = ctx.orig();
        logInfo("Instrumentation.newApplication returned");
        return app;
    };

Application.attach
    .overload("android.content.Context")
    .impl = function (ctx) {
        logInfo("Application.attach entered: " + ctx.thisObj.$className);
        ctx.orig();
        logInfo("Application.attach returned: " + ctx.thisObj.$className);
    };

Activity.onResume.impl = function (ctx) {
    logInfo("Activity.onResume entered: " + ctx.thisObj.$className);
    return ctx.orig();
};

logInfo("gate_probe hooks installed");
