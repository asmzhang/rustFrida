## Java Hook

```js
Java.ready(function() {
    var Activity = Java.use("android.app.Activity");

    // hook 实例方法（return 值就是方法返回值）
    Activity.onResume.impl = function(ctx) {
        console.log("onResume:", ctx.thisObj.$className);
        return ctx.orig();
    };

    // hook 构造函数
    var MyClass = Java.use("com.example.MyClass");
    MyClass.$init.impl = function(ctx) {
        console.log("new MyClass, arg0 =", ctx.args[0]);
        return ctx.orig();
    };

    // 修改参数
    MyClass.test.impl = function(ctx) {
        return ctx.orig("patched_arg");
    };

    // 指定 overload（Java 类型名或 JNI 签名都行）
    MyClass.foo.overload("int", "java.lang.String").impl = function(ctx) {
        return ctx.orig();
    };

    // 移除 hook
    Activity.onResume.impl = null;
});
```

### Java.use 对象操作

```js
var JString = Java.use("java.lang.String");
var s = JString.$new("hello");     // 创建对象
console.log(s.length());           // 调实例方法
console.log(s.$className);         // 类名

var Process = Java.use("android.os.Process");
console.log(Process.myPid());      // 调静态方法
```

### Java.ready

Spawn 模式下 app ClassLoader 未就绪，用 `Java.ready` 延迟执行。PID 注入模式下立即执行。

### Stealth 模式（Java hook）

```js
Java.setStealth(0);  // Normal: mprotect 直写
Java.setStealth(1);  // WxShadow: shadow 页，CRC 校验不可见
Java.setStealth(2);  // Recomp: 代码页重编译
Java.getStealth();   // 查询当前模式 (0/1/2)
```

须在 `Java.use().impl` 之前设置。

### Deopt API

```js
Java.deopt();                  // 清空 JIT 缓存（InvalidateAllMethods）
Java.deoptimizeBootImage();    // boot image AOT 降级为 interpreter (API >= 26)
Java.deoptimizeEverything();   // 全局强制解释执行
Java.deoptimizeMethod("com.example.Test", "foo", "(I)V");  // 单方法降级
```

手动调用的工具函数，hook 流程不自动使用。

### API 速查

| API | 参数 | 返回 |
| --- | --- | --- |
| `Java.use(className)` | `string` | `JavaClassWrapper` |
| `Class.$new(...args)` | 任意 | `JavaObjectProxy` |
| `Class.method.impl = fn` | `(ctx: JavaHookContext) => any` | setter |
| `Class.method.impl = null` | — | setter |
| `Class.method.overload(...types)` | `string...` | `MethodWrapper` |
| `Java.ready(fn)` | `() => void` | `void` |
| `Java.deopt()` | — | `boolean` |
| `Java.deoptimizeBootImage()` | — | `boolean` |
| `Java.deoptimizeEverything()` | — | `boolean` |
| `Java.deoptimizeMethod(cls, method, sig)` | `string, string, string` | `boolean` |
| `Java.setStealth(mode)` | `number (0/1/2)` | — |
| `Java.getStealth()` | — | `number` |
| `Java.getField(objPtr, cls, field, sig)` | `AddressLike, string, string, string` | `any` |

---

