var getpid = Module.findExportByName("libc.so", "getpid");
console.log("[attach] getpid export => " + getpid);

hook(getpid, function (ctx) {
    console.log("[attach] getpid hooked");
    ctx.orig();
    return 42424;
});

var result = callNative(getpid);
console.log("[attach] callNative(getpid) => " + result);
