# 内置对象 (Memory, Module, ptr, console)

## Memory

| API | 参数 | 返回 |
| --- | --- | --- |
| `Memory.readU8(addr)` | `AddressLike` | `number` |
| `Memory.readU16(addr)` | `AddressLike` | `number` |
| `Memory.readU32(addr)` | `AddressLike` | `bigint` |
| `Memory.readU64(addr)` | `AddressLike` | `bigint` |
| `Memory.readPointer(addr)` | `AddressLike` | `NativePointer` |
| `Memory.readCString(addr)` | `AddressLike` | `string` (最多 4096B) |
| `Memory.readUtf8String(addr)` | `AddressLike` | `string` |
| `Memory.readByteArray(addr, len)` | `AddressLike, number` | `ArrayBuffer` |
| `Memory.writeU8(addr, value)` | `AddressLike, number` | `undefined` |
| `Memory.writeU16(addr, value)` | `AddressLike, number` | `undefined` |
| `Memory.writeU32(addr, value)` | `AddressLike, number` | `undefined` |
| `Memory.writeU64(addr, value)` | `AddressLike, bigint` | `undefined` |
| `Memory.writePointer(addr, value)` | `AddressLike, AddressLike` | `undefined` |

无效地址抛 `RangeError`，不会崩进程。

## Module

| API | 参数 | 返回 |
| --- | --- | --- |
| `Module.findExportByName(module, symbol)` | `string, string` | `NativePointer \| null` |
| `Module.findBaseAddress(module)` | `string` | `NativePointer \| null` |
| `Module.findByAddress(addr)` | `AddressLike` | `ModuleInfo \| null` |
| `Module.enumerateModules()` | — | `ModuleInfo[]` |

## ptr / NativePointer

```js
var p = ptr("0x7f12345678");   // hex string / number / BigInt / NativePointer
p.add(0x100)                   // → NativePointer
p.sub(offset)                  // → NativePointer
p.toString()                   // → "0x7f12345678"
```

| API | 参数 | 返回 |
| --- | --- | --- |
| `ptr(value)` | `number \| bigint \| string \| NativePointer` | `NativePointer` |
| `p.add(offset)` | `AddressLike` | `NativePointer` |
| `p.sub(offset)` | `AddressLike` | `NativePointer` |
| `p.toString()` | — | `string` |
| `p.toNumber()` | — | `bigint` |

## console

`console.log(...)` / `console.info(...)` / `console.warn(...)` / `console.error(...)` / `console.debug(...)`

