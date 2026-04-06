# JS API 基础与全局变量


### 全局对象一览

`console`, `ptr()`, `Memory`, `Module`, `hook()`, `unhook()`, `callNative()`, `qbdi`, `Java`, `Jni`

### 常用类型别名

| 类型名 | 实际含义 |
| --- | --- |
| `AddressLike` | `NativePointer \| number \| bigint \| "0x..."` |
| `NativePointer` | `ptr()` 创建的指针对象 |
| `JavaObjectProxy` | `Java.use()` / Java hook 中返回的 Java 对象代理 |

### 结构体 / 上下文对象

```ts
type ModuleInfo = {
  name: string; base: NativePointer; size: number; path: string
}

type NativeHookContext = {
  x0 ~ x30: number | bigint    // ARM64 通用寄存器
  sp: number | bigint
  pc: number | bigint
  trampoline: number | bigint
  orig(): number | bigint       // 调用原函数，返回值写入 x0
}

type JavaHookContext = {
  thisObj?: JavaObjectProxy     // 实例方法的 this（静态方法无）
  args: any[]                   // 参数数组
  env: number | bigint          // JNIEnv*
  orig(...args: any[]): any     // 调原方法，不传参用原始参数
}

type JniEntry = { name: string; index: number; address: NativePointer }

type JNINativeMethodInfo = {
  address: NativePointer; namePtr: NativePointer; sigPtr: NativePointer
  fnPtr: NativePointer; name: string | null; sig: string | null
}
```

---

