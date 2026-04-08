Java.ready(function () {
    var Log = Java.use("android.util.Log");
    var JString = Java.use("java.lang.String");
    var MainActivity = Java.use("com.asmzhang.testapp.MainActivity");

    function logInfo(msg) {
        console.log("[spawn] " + msg);
        Log.i("RustFridaJS", msg);
    }

    function logError(msg) {
        console.log("[spawn] " + msg);
        Log.e("RustFridaJS", msg);
    }

    function updateSampleText(activity, text, stage) {
        var res = activity.getResources();
        var viewId = res.getIdentifier(
            JString.$new("sample_text"),
            JString.$new("id"),
            activity.getPackageName()
        );
        var tv = viewId ? activity.findViewById(viewId) : null;
        if (tv !== null) {
            tv.$call("setText", "(Ljava/lang/CharSequence;)V", JString.$new(text));
            logInfo("sampleText updated in " + stage + " => " + text);
        } else {
            logError("sampleText view not found in " + stage);
        }
    }

    logInfo("Java.ready fired, installing MainActivity hooks");

    MainActivity.stringFromJNI.impl = function (ctx) {
        logInfo("hooked MainActivity.stringFromJNI()");
        return "Hello from rustFrida";
    };

    MainActivity.onCreate.impl = function (ctx) {
        logInfo("hooked MainActivity.onCreate()");
        var ret = ctx.orig();

        try {
            updateSampleText(ctx.thisObj, "HOOK_OK_FROM_ONCREATE", "onCreate");
        } catch (e) {
            logError("onCreate verification failed: " + e);
        }

        return ret;
    };

    MainActivity.onResume.impl = function (ctx) {
        logInfo("hooked MainActivity.onResume()");
        var ret = ctx.orig();

        try {
            updateSampleText(ctx.thisObj, "HOOK_OK_FROM_ONRESUME", "onResume");
        } catch (e) {
            logError("onResume verification failed: " + e);
        }

        return ret;
    };

    logInfo("MainActivity hooks installed");
});
