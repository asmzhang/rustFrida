## JNI API

```js
Jni.addr("RegisterNatives")       // → NativePointer
Jni.FindClass                     // 属性直接取地址
Jni.find("FindClass")             // → { name, index, address }
Jni.table                         // 整张 JNI 函数表
Jni.addr(envPtr, "FindClass")     // 指定 JNIEnv
```

### Jni.helper

```js
Jni.helper.env.ptr                         // 当前线程 JNIEnv*
Jni.helper.env.getClassName(jclass)        // → "android.app.Activity"
Jni.helper.env.getObjectClassName(jobject)  // → 对象的类名
Jni.helper.env.readJString(jstring)        // → JS string
Jni.helper.env.getObjectClass(obj)         // → jclass
Jni.helper.env.getSuperclass(clazz)        // → jclass
Jni.helper.env.isSameObject(a, b)          // → boolean
Jni.helper.env.isInstanceOf(obj, clazz)    // → boolean
Jni.helper.env.exceptionCheck()            // → boolean
Jni.helper.env.exceptionClear()

Jni.helper.structs.JNINativeMethod.readArray(addr, count)  // → JNINativeMethodInfo[]
Jni.helper.structs.jvalue.readArray(addr, typesOrSig)      // → any[]
```

### API 速查

| API | 参数 | 返回 |
| --- | --- | --- |
| `Jni.addr(name)` | `string` | `NativePointer` |
| `Jni.addr(env, name)` | `AddressLike, string` | `NativePointer` |
| `Jni.find(name)` | `string` | `JniEntry` |
| `Jni.entries()` | — | `JniEntry[]` |
| `Jni.table` | — | `Record<string, JniEntry>` |
| `Jni.helper.env.getClassName(clazz)` | `AddressLike` | `string \| null` |
| `Jni.helper.env.readJString(jstr)` | `AddressLike` | `string \| null` |
| `Jni.helper.structs.JNINativeMethod.readArray(addr, count)` | `AddressLike, number` | `JNINativeMethodInfo[]` |

### 实战：监控 RegisterNatives

```js
hook(Jni.addr("RegisterNatives"), function(ctx) {
    var cls = Jni.helper.env.getClassName(ctx.x1);
    var count = Number(ctx.x3);
    console.log(cls + " (" + count + " methods)");

    var methods = Jni.helper.structs.JNINativeMethod.readArray(ptr(ctx.x2), count);
    for (var i = 0; i < methods.length; i++) {
        var m = methods[i];
        var mod = Module.findByAddress(m.fnPtr);
        console.log("  " + m.name + " " + m.sig + " → " + mod.name + "+" + m.fnPtr.sub(mod.base));
    }
    return ctx.orig();
}, 1);
```

---

