## Native Hook

```js
// 基本 hook — 透传
hook(Module.findExportByName("libc.so", "open"), function(ctx) {
    console.log("open:", Memory.readCString(ptr(ctx.x0)));
    return ctx.orig();
});

// 修改返回值
hook(Module.findExportByName("libc.so", "getpid"), function(ctx) {
    ctx.orig();
    return 12345;              // 调用方拿到 12345
});

// 修改参数 — 通过 ctx 属性
hook(target, function(ctx) {
    ctx.x0 = ptr("0x1234");   // 改第一个参数
    ctx.x1 = 100;             // 改第二个参数
    return ctx.orig();         // 用修改后的参数调原函数
});

// 修改参数 — 通过 orig() 传参（按顺序覆盖 x0-xN）
hook(target, function(ctx) {
    return ctx.orig(ptr("0x1234"), 100);
});

// 不 return 也行 — ctx.x0 赋值会同步回 C 层
hook(Module.findExportByName("libc.so", "getuid"), function(ctx) {
    ctx.orig();
    ctx.x0 = 77777;           // 调用方拿到 77777
});

// 移除 hook
unhook(Module.findExportByName("libc.so", "open"));

// 直接调用 native 函数（最多 6 个参数，走 x0-x5）
var pid = callNative(Module.findExportByName("libc.so", "getpid"));
```

### Stealth 模式

```js
hook(target, callback, Hook.NORMAL)     // 0: mprotect 直写（默认）
hook(target, callback, Hook.WXSHADOW)   // 1: 内核 shadow 页，/proc/mem 不可见
hook(target, callback, Hook.RECOMP)     // 2: 代码页重编译，仅 4B patch
hook(target, callback, 1)               // 数字也行
hook(target, callback, true)            // true = WXSHADOW
```

### API 速查

| API | 参数 | 返回 |
| --- | --- | --- |
| `hook(target, callback, stealth?)` | `AddressLike, Function, number?` | `boolean` |
| `unhook(target)` | `AddressLike` | `boolean` |
| `callNative(func, ...args)` | `AddressLike, ...AddressLike` (最多6个) | `number \| bigint` |
| `diagAllocNear(addr)` | `AddressLike` | `undefined` |

---

