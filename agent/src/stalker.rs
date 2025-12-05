/* This example is in the public domain */
use crate::{log_msg, GLOBAL_STREAM, OUTPUT_PATH};
use crossbeam_channel::{bounded, Sender};
use frida_gum::interceptor::{Interceptor, InvocationContext, InvocationListener, ProbeListener};
use frida_gum::stalker::{Event, EventMask, EventSink, Stalker, Transformer};
use frida_gum::{Gum, ModuleMap, NativePointer, Process};
use lazy_static::lazy_static;
use prost::Message;
use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::ptr::null_mut;
use std::sync::{Arc, Mutex, Once, OnceLock};
use std::thread;
use qbdi::{FPRState, GPRState, InstPosition, RWord, VMAction, VirtualStack, VM, VMOptions, VMRef};
use qbdi::ffi::{InstCallback, InstPosition_QBDI_PREINST, VMAction_QBDI_CONTINUE, VMInstanceRef, VMCallback, MemoryAccessType_QBDI_MEMORY_READ, VMEvent_QBDI_EXEC_TRANSFER_RETURN, VMEvent_QBDI_SEQUENCE_ENTRY};
use std::ffi::CString;
use libc::stat;

// Android log priority levels
const ANDROID_LOG_INFO: i32 = 4;

extern "C" {
    fn __android_log_print(prio: i32, tag: *const i8, fmt: *const i8, ...) -> i32;
}

fn logcat(msg: &str) {
    let tag = CString::new("rustFrida").unwrap();
    let fmt = CString::new("%s").unwrap();
    let msg_c = CString::new(msg).unwrap_or_else(|_| CString::new("invalid msg").unwrap());
    unsafe {
        __android_log_print(
            ANDROID_LOG_INFO,
            tag.as_ptr() as *const i8,
            fmt.as_ptr() as *const i8,
            msg_c.as_ptr() as *const i8,
        );
    }
}

// 寄存器变化记录（只记录有变化的寄存器）
#[derive(Clone, PartialEq, Message)]
struct RegChange {
    #[prost(uint32, tag = "1")]
    reg_num: u32,        // 寄存器编号 (0-28 对应 X0-X28)
    #[prost(uint64, tag = "2")]
    value: u64,          // 寄存器值
}

// 原始指令消息（在通道中传输，包含完整寄存器）
// 使用 Arc 共享数据，避免每次克隆
#[derive(Clone)]
struct RawInstrMessage {
    addr: u64,
    bytes: Arc<Vec<u8>>,    // 使用 Arc 共享，避免克隆
    module: Arc<String>,     // 使用 Arc 共享，避免克隆
    regs: [u64; 32],         // 完整的寄存器值（X0-X28 + FP + LR + SP，用于后台比对）
}

// 定义指令跟踪消息（最终写入文件的 protobuf 格式）
#[derive(Clone, PartialEq, Message)]
struct InstrMessage {
    #[prost(uint64, tag = "1")]
    addr: u64,
    #[prost(bytes, tag = "2")]
    bytes: Vec<u8>,      // ARM64 指令字节码（4字节）
    #[prost(message, repeated, tag = "3")]
    ctx: Vec<RegChange>, // 只记录变化的寄存器
}

// 内存访问记录（用于 QBDI mem_acc_cb）
#[derive(Clone, PartialEq, Message)]
pub struct MemAccess {
    #[prost(uint64, tag = "1")]
    inst_addr: u64,       // 发出访问的指令地址
    #[prost(uint64, tag = "2")]
    access_addr: u64,     // 被访问的内存地址
    #[prost(uint64, tag = "3")]
    value: u64,           // 读取的值
    #[prost(uint32, tag = "4")]
    size: u32,            // 访问大小（字节）
}

// 外部调用返回记录（用于 EXEC_TRANSFER_RETURN 事件）
#[derive(Clone, PartialEq, Message)]
pub struct ExternalReturn {
    #[prost(uint64, tag = "1")]
    return_addr: u64,     // 返回到的地址（即调用指令的下一条指令）
    #[prost(uint64, tag = "2")]
    return_value: u64,    // 返回值 (x0)
}

// 内存区域信息
#[derive(Clone, PartialEq, Message)]
struct MemoryRegion {
    #[prost(uint64, tag = "1")]
    start_addr: u64,
    #[prost(uint64, tag = "2")]
    end_addr: u64,
    #[prost(string, tag = "3")]
    permissions: String,
    #[prost(uint64, tag = "4")]
    offset: u64,
    #[prost(string, tag = "5")]
    dev: String,
    #[prost(uint64, tag = "6")]
    inode: u64,
    #[prost(string, tag = "7")]
    pathname: String,
    #[prost(bytes, tag = "8")]
    data: Vec<u8>,
}

// 内存快照头部信息（用于流式写入）
#[derive(Clone, PartialEq, Message)]
struct SnapshotHeader {
    #[prost(uint64, tag = "1")]
    timestamp: u64,
    #[prost(uint32, tag = "2")]
    pid: u32,
    #[prost(uint32, tag = "3")]
    region_count: u32,  // 区域总数（可选，用于读取时预分配）
}

// 内存快照（完整版，保留用于可能的非流式场景）
// #[derive(Clone, PartialEq, Message)]
// struct MemorySnapshot {
//     #[prost(uint64, tag = "1")]
//     timestamp: u64,
//     #[prost(uint32, tag = "2")]
//     pid: u32,
//     #[prost(message, repeated, tag = "3")]
//     regions: Vec<MemoryRegion>,
// }


// 全局 Stalker 包装器（无锁共享）
struct StalkerCell(UnsafeCell<Stalker>);
unsafe impl Sync for StalkerCell {}
unsafe impl Send for StalkerCell {}

// 全局 ModuleMap 包装器（无锁共享）
struct ModuleMapCell(UnsafeCell<ModuleMap>);
unsafe impl Sync for ModuleMapCell {}
unsafe impl Send for ModuleMapCell {}

// 使用 OnceLock 存储全局 Stalker
static GLOBAL_STALKER: std::sync::OnceLock<StalkerCell> = std::sync::OnceLock::new();

// 使用 OnceLock 存储全局 ModuleMap
static GLOBAL_MODULE_MAP: std::sync::OnceLock<ModuleMapCell> = std::sync::OnceLock::new();
static GLOBAL_PROC:std::sync::OnceLock<ModuleMapCell> = std::sync::OnceLock::new();

// 全局 target 变量
pub static GLOBAL_TARGET: OnceLock<usize> = OnceLock::new();

// 全局原始函数指针（由 replace 返回的 trampoline）
pub static GLOBAL_ORIGINAL: OnceLock<usize> = OnceLock::new();

// 全局 QBDI VM 包装器
struct VMCell(UnsafeCell<VM>);
unsafe impl Sync for VMCell {}
unsafe impl Send for VMCell {}

static GLOBAL_VM: OnceLock<VMCell> = OnceLock::new();

// 全局 Interceptor 包装器（无锁共享）
struct InterceptorCell(UnsafeCell<Interceptor>);
unsafe impl Sync for InterceptorCell {}
unsafe impl Send for InterceptorCell {}

// 使用 OnceLock 存储全局 Interceptor
static GLOBAL_INTERCEPTOR: std::sync::OnceLock<InterceptorCell> = std::sync::OnceLock::new();

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };

    // 全局 map: 存储基本块地址 -> 指令数量的映射
    static ref BLOCK_COUNT_MAP: Mutex<HashMap<u64, usize>> = Mutex::new(HashMap::new());

    // QBDI 地址发送通道（只发送 addr，用于 qfollow）
    static ref QBDI_ADDR_SENDER: Sender<RWord> = {
        let (sender, receiver) = bounded::<RWord>(100000);

        // 启动后台工作线程
        thread::spawn(move || {
            // 获取输出路径，构造日志文件路径
            let log_path = match OUTPUT_PATH.get() {
                Some(base) => format!("{}/trace.pb", base),
                None => {
                    log_msg("错误: OUTPUT_PATH 未设置，无法创建 QBDI 日志文件".to_string());
                    return;
                }
            };

            let mut log_file = match OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&log_path)
            {
                Ok(f) => f,
                Err(e) => {
                    log_msg(format!("无法打开 QBDI 日志文件 {}: {}", log_path, e));
                    return;
                }
            };

            while let Ok(addr) = receiver.recv() {
                // log_msg(format!("{:x}",addr));
                // 紧凑二进制格式：直接写入 u64 小端字节（8字节/地址）
                if let Err(e) = log_file.write_all(&addr.to_le_bytes()) {
                    log_msg(format!("写入 QBDI 日志失败: {}", e));
                }
            }
            log_file.flush().unwrap();
        });

        sender
    };

    // 内存访问记录通道
    static ref MEM_ACCESS_SENDER: Sender<MemAccess> = {
        let (sender, receiver) = bounded::<MemAccess>(100000);

        // 启动后台工作线程
        thread::spawn(move || {
            // 获取输出路径，构造日志文件路径
            let log_path = match OUTPUT_PATH.get() {
                Some(base) => format!("{}/mem_access.pb", base),
                None => {
                    log_msg("错误: OUTPUT_PATH 未设置，无法创建内存访问日志文件".to_string());
                    return;
                }
            };

            let mut log_file = match OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&log_path)
            {
                Ok(f) => f,
                Err(e) => {
                    log_msg(format!("无法打开内存访问日志文件 {}: {}", log_path, e));
                    return;
                }
            };

            while let Ok(mem_acc) = receiver.recv() {
                // log_msg(format!("read inst:{:x}",mem_acc.inst_addr));
                // 使用 length-delimited 编码写入 protobuf
                let mut buf = Vec::new();
                if let Err(e) = mem_acc.encode_length_delimited(&mut buf) {
                    log_msg(format!("MemAccess 编码失败: {}", e));
                    continue;
                }

                if let Err(e) = log_file.write_all(&buf) {
                    log_msg(format!("写入内存访问日志失败: {}", e));
                }
            }
            log_file.flush().unwrap();
        });

        sender
    };

    // 外部调用返回记录通道（用于 EXEC_TRANSFER_RETURN 事件）
    static ref EXTERNAL_RETURN_SENDER: Sender<ExternalReturn> = {
        let (sender, receiver) = bounded::<ExternalReturn>(100000);

        // 启动后台工作线程
        thread::spawn(move || {
            // 获取输出路径，构造日志文件路径
            let log_path = match OUTPUT_PATH.get() {
                Some(base) => format!("{}/external_return.pb", base),
                None => {
                    log_msg("错误: OUTPUT_PATH 未设置，无法创建外部返回日志文件".to_string());
                    return;
                }
            };

            let mut log_file = match OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&log_path)
            {
                Ok(f) => f,
                Err(e) => {
                    log_msg(format!("无法打开外部返回日志文件 {}: {}", log_path, e));
                    return;
                }
            };

            while let Ok(ext_ret) = receiver.recv() {
                // 使用 length-delimited 编码写入 protobuf
                let mut buf = Vec::new();
                if let Err(e) = ext_ret.encode_length_delimited(&mut buf) {
                    log_msg(format!("ExternalReturn 编码失败: {}", e));
                    continue;
                }
                if let Err(e) = log_file.write_all(&buf) {
                    log_msg(format!("写入外部返回日志失败: {}", e));
                }
            }
            log_file.flush().unwrap();
        });

        sender
    };

    // 创建有界通道（限制内存占用，容量 10000 条消息，约 2.5MB）
    static ref INSTR_SENDER: Sender<RawInstrMessage> = {
        let (sender, receiver) = bounded::<RawInstrMessage>(100000);

        // 启动后台工作线程
        thread::spawn(move || {
            // 获取输出路径，构造日志文件路径
            let log_path = match OUTPUT_PATH.get() {
                Some(base) => format!("{}/trace.pb", base),
                None => {
                    log_msg("错误: OUTPUT_PATH 未设置，无法创建日志文件".to_string());
                    return;
                }
            };

            let mut log_file = match OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
            {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("无法打开日志文件 {}: {}", log_path, e);
                    return;
                }
            };

            while let Ok(raw_msg) = receiver.recv() {
                // 紧凑二进制格式：直接写入 u64 小端字节（8字节/地址）
                if let Err(e) = log_file.write_all(&raw_msg.addr.to_le_bytes()) {
                    log_msg(format!("写入日志失败: {}", e));
                }
            }
        });

        sender
    };
}

// 解析 /proc/self/maps 中的单行
fn parse_maps_line(line: &str) -> Option<(u64, u64, String, u64, String, u64, String)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }

    // 解析地址范围
    let addr_range: Vec<&str> = parts[0].split('-').collect();
    if addr_range.len() != 2 {
        return None;
    }
    let start_addr = u64::from_str_radix(addr_range[0], 16).ok()?;
    let end_addr = u64::from_str_radix(addr_range[1], 16).ok()?;

    // 权限
    let permissions = parts[1].to_string();

    // 偏移
    let offset = u64::from_str_radix(parts[2], 16).ok()?;

    // 设备号
    let dev = parts[3].to_string();

    // inode
    let inode = parts[4].parse::<u64>().ok()?;

    // 路径名（可能不存在）
    let pathname = if parts.len() > 5 {
        parts[5..].join(" ")
    } else {
        String::new()
    };

    Some((start_addr, end_addr, permissions, offset, dev, inode, pathname))
}

// 分块大小：4MB，避免一次性分配过大内存导致栈溢出
const MEMORY_CHUNK_SIZE: usize = 4 * 1024 * 1024;

// 直接读取指定地址范围的内存（无需 /proc/self/mem）
// 注意：对于大区域，应使用 write_memory_region_chunked 分块写入
fn read_memory_region(start_addr: u64, size: usize) -> std::io::Result<Vec<u8>> {
    unsafe {
        // 直接通过指针访问本进程内存
        let ptr = start_addr as *const u8;
        let slice = std::slice::from_raw_parts(ptr, size);
        Ok(slice.to_vec())
    }
}

// 分块写入内存区域到文件，避免一次性加载整个区域导致内存溢出
fn write_memory_region_chunked<W: Write>(
    output: &mut W,
    start_addr: u64,
    end_addr: u64,
    permissions: &str,
    offset: u64,
    pathname: &str,
) -> std::io::Result<()> {
    let total_size = (end_addr - start_addr) as usize;
    let mut current_addr = start_addr;
    let mut current_offset = offset;
    let mut chunk_index = 0u32;

    while current_addr < end_addr {
        let remaining = (end_addr - current_addr) as usize;
        let chunk_size = remaining.min(MEMORY_CHUNK_SIZE);
        let chunk_end = current_addr + chunk_size as u64;

        // 读取当前块的内存数据
        let data = unsafe {
            let ptr = current_addr as *const u8;
            let slice = std::slice::from_raw_parts(ptr, chunk_size);
            slice.to_vec()
        };

        // 创建区域消息（包含分块信息）
        let region = MemoryRegion {
            start_addr: current_addr,
            end_addr: chunk_end,
            permissions: permissions.to_string(),
            offset: current_offset,
            dev: String::new(),
            inode: chunk_index as u64,  // 复用 inode 字段标记分块索引
            pathname: if total_size > MEMORY_CHUNK_SIZE {
                format!("{}#chunk{}", pathname, chunk_index)
            } else {
                pathname.to_string()
            },
            data,
        };

        // 编码并写入
        let mut region_buf = Vec::with_capacity(chunk_size + 256);
        region.encode_length_delimited(&mut region_buf).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("Region 编码失败: {}", e))
        })?;
        output.write_all(&region_buf)?;

        current_addr = chunk_end;
        current_offset += chunk_size as u64;
        chunk_index += 1;
    }

    Ok(())
}

// Dump 内存快照到文件（流式写入版本，读取 /proc/self/maps）
fn dump_memory_snapshot(output_path: &str) -> std::io::Result<()> {
    use std::io::BufRead;

    // 读取 /proc/self/maps
    let maps_file = File::open("/proc/self/maps")?;
    let reader = std::io::BufReader::new(maps_file);

    // 先收集所有需要 dump 的区域
    let mut regions_to_dump: Vec<(u64, u64, String, u64, String, u64, String)> = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if let Some((start_addr, end_addr, permissions, offset, dev, inode, pathname)) = parse_maps_line(&line) {
            // 只 dump 包含 .so 的可读区域
            if ( (pathname.contains(".so") && pathname.contains("/data") )|| pathname.contains("base.apk")) && permissions.contains('r') {
                regions_to_dump.push((start_addr, end_addr, permissions, offset, dev, inode, pathname));
            }
        }
    }

    // 打开输出文件
    let mut output_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path)?;

    // 获取当前时间戳
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 获取当前进程 PID
    let pid = std::process::id();

    // 1. 先写入头部信息
    let header = SnapshotHeader {
        timestamp,
        pid,
        region_count: regions_to_dump.len() as u32,
    };
    let mut header_buf = Vec::new();
    header.encode_length_delimited(&mut header_buf).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("Header 编码失败: {}", e))
    })?;
    output_file.write_all(&header_buf)?;

    // 2. 流式处理每个内存区域
    for (start_addr, end_addr, permissions, offset, dev, inode, pathname) in regions_to_dump {
        // log_msg(format!("Dumping: {} 0x{:x}-0x{:x}", pathname, start_addr, end_addr));

        // 使用分块写入，避免大内存区域导致栈溢出
        if let Err(e) = write_memory_region_chunked(
            &mut output_file,
            start_addr,
            end_addr,
            &permissions,
            offset,
            &pathname,
        ) {
            log_msg(format!("写入内存区域失败 0x{:x}-0x{:x}: {}", start_addr, end_addr, e));
            // 继续处理下一个区域，不中断整个 dump
            continue;
        }
    }

    // 刷新缓冲区确保数据写入磁盘
    output_file.flush()?;

    Ok(())
}

/// 获取全局 Stalker 的可变引用（无锁定，调用方需保证线程安全）
#[inline]
fn get_stalker() -> &'static mut Stalker {
    let cell = GLOBAL_STALKER.get_or_init(|| {
        StalkerCell(UnsafeCell::new(Stalker::new(&GUM)))
    });
    unsafe { &mut *cell.0.get() }
}

/// 获取全局 Interceptor 的可变引用（无锁定，调用方需保证线程安全）
#[inline]
pub fn get_interceptor() -> &'static mut Interceptor {
    let cell = GLOBAL_INTERCEPTOR.get_or_init(|| {
        InterceptorCell(UnsafeCell::new(Interceptor::obtain(&GUM)))
    });
    unsafe { &mut *cell.0.get() }
}

/// 获取全局 ModuleMap 的引用（无锁定，调用方需保证线程安全）
/// 注意：ModuleMap 在首次调用时初始化，之后可以调用 update_module_map() 手动更新
#[inline]
fn get_module_map() -> &'static ModuleMap {
    let cell = GLOBAL_MODULE_MAP.get_or_init(|| {
        let mut map = ModuleMap::new();
        map.update();
        ModuleMapCell(UnsafeCell::new(map))
    });
    unsafe { &*cell.0.get() }
}

/// 更新全局 ModuleMap（当有新模块加载时调用）
/// 注意：这个操作不是线程安全的，调用前需要确保没有其他线程在读取 ModuleMap
pub fn update_module_map() {
    let cell = GLOBAL_MODULE_MAP.get_or_init(|| {
        let mut map = ModuleMap::new();
        map.update();
        ModuleMapCell(UnsafeCell::new(map))
    });
    unsafe {
        (*cell.0.get()).update();
    }
    log_msg("ModuleMap 已更新".to_string());
}

struct SampleEventSink;

impl EventSink for SampleEventSink {
    fn query_mask(&mut self) -> EventMask {
        EventMask::None
    }

    fn start(&mut self) {
        println!("start");
    }

    fn process(&mut self, _event: &Event) {
        println!("process");
    }

    fn flush(&mut self) {
        println!("flush");
    }

    fn stop(&mut self) {
        println!("stop");
    }
}

/// 启动内存 dump 线程（非阻塞）
///
/// # 参数
/// - `output_path`: 内存快照输出路径
///
/// # 返回
/// - `std::thread::JoinHandle`: 线程句柄，可用于等待 dump 完成
pub fn spawn_memory_dump_thread(output_path: String) -> thread::JoinHandle<()> {
    thread::spawn(move || {

        match dump_memory_snapshot(&output_path) {
            Ok(_) => {
                log_msg(format!("内存快照已保存到: {}\n", output_path))
            }
            Err(e) => {
                log_msg(format!("内存快照保存失败: {}\n", e))
            }
        }
    })
}

pub fn start_dump_mem(){
    // 在开始追踪前启动内存 dump 线程（非阻塞）
    let snapshot_path = match OUTPUT_PATH.get() {
        Some(base) => format!("{}/memory_snapshot.pb", base),
        None => {
            log_msg("错误: OUTPUT_PATH 未设置，无法保存内存快照\n".to_string());
            return;
        }
    };

    let _dump_handle = spawn_memory_dump_thread(snapshot_path);
}

pub fn follow(tid:usize) {
    // let stalker = get_stalker();
    let mut stalker = Stalker::new(&GUM);
    // update_module_map();
    // let proc = Process::obtain(&GUM);
    // let mut mdmap = ModuleMap::new();
    // mdmap.update();

    // 存储模块信息：base -> (size, path, name)
    // let mut modules: BTreeMap<usize, (usize, String, String)> = BTreeMap::new();
    // for md in proc.enumerate_modules(){
    //     modules.insert(
    //         md.range().base_address().0 as usize,
    //         (md.range().size(), md.path(), md.name())
    //     );
    // }
    // let mut log_file = OpenOptions::new()
    //     .create(true)
    //     .append(true)
    //     .open("/data/data/com.example.tracersample/files/wwb.log")
    //     .expect("Failed to open log file");

    let transformer = Transformer::from_callback(&GUM,  |mut basic_block, _output| {
        // 优化：在第一条指令处理时获取模块信息，basic block 内的指令通常属于同一模块
        // let proc = Process::obtain(&GUM);
        let mdmap = get_module_map();

        // 用于缓存模块信息（在 basic block 内复用）
        let mut module_info: Option<(String, u64, String)> = None;
        let mut should_trace: Option<bool> = None;

        // 遍历 basic block 中的每条指令
        for instr in basic_block {
            let addr = instr.instr().address();

            // 第一次迭代时获取模块信息
            if module_info.is_none() {
                let (md_path, module_base, module_name) = match mdmap.find(addr) {
                    Some(m) => {
                        (m.path().to_string(), m.range().base_address().0 as u64, m.name().to_string())
                    },
                    None => {
                        ("unknown".to_string(), 0u64, "unknown".to_string())
                    }
                };

                // 判断是否需要追踪
                should_trace = Some(!(md_path.contains("apex") ||
                                     md_path.contains("system") ||
                                     md_path.contains("unknown") ||
                                     md_path.contains("memfd")));

                module_info = Some((md_path, module_base, module_name));
            }

            // 如果不需要追踪，直接保持指令
            if !should_trace.unwrap() {
                instr.keep();
                continue;
            }

            // 获取缓存的模块信息
            let (_, module_base, module_name) = module_info.as_ref().unwrap();

            // 获取指令字节码（ARM64 指令固定 4 字节）
            let instr_bytes = instr.instr().bytes();
            let bytes = Arc::new(instr_bytes[0..4].to_vec());

            // 格式化模块名（每条指令一次，但使用 Arc 共享）
            let md_name = Arc::new(format!("{}+0x{:x}", module_name, addr - module_base));

            unsafe {
                instr.put_callout(move |_cpu_context| {
                    let a = 1 + 2;
                    log_msg(format!("{:x}",_cpu_context.pc()));
                    // // 直接读取寄存器值，不做任何比对（比对在后台线程进行）
                    // let mut regs = [0u64; 32];
                    // // 复制 X0-X28
                    // regs[0..29].copy_from_slice(&(*_cpu_context.cpu_context).x);
                    // // 添加 FP, LR, SP (索引 29, 30, 31)
                    // regs[29] = _cpu_context.fp();
                    // regs[30] = _cpu_context.lr();
                    // regs[31] = _cpu_context.sp();
                    //
                    // // 发送原始消息，Arc 会自动增加引用计数，无需克隆底层数据
                    // let _ = INSTR_SENDER.try_send(RawInstrMessage {
                    //     addr,
                    //     bytes: Arc::clone(&bytes),
                    //     module: Arc::clone(&md_name),
                    //     regs,
                    // });
                });
            }
            instr.keep();
        }
    });

    // let mut event_sink = SampleEventSink;
    log_msg(format!("following {}",tid));
    if tid == 0 {
        stalker.follow_me(&transformer,Some(&mut SampleEventSink));
    }else {
        stalker.follow(tid,&transformer, Some(&mut SampleEventSink));
    }

}

struct OpenListener;
struct plistener;

impl InvocationListener for OpenListener {
    fn on_enter(&mut self, _context: InvocationContext) {
        log_msg(format!("oopps stalker {}",_context.thread_id()));
        // start_dump_mem();
        // follow(_context.thread_id() as usize);
    }

    fn on_leave(&mut self, _context: InvocationContext) {
        GLOBAL_STREAM.get().unwrap().write_all("end trace".as_bytes());
        get_stalker().deactivate();
    }
}

/// 从 /proc/self/maps 查找库的基址
fn find_lib_base(lib_name: &str) -> Option<usize> {
    use std::io::BufRead;
    let file = File::open("/proc/self/maps").ok()?;
    let reader = std::io::BufReader::new(file);
    // let stalker = get_stalker();

    let mut result = None;
    for line in reader.lines() {
        let line = line.ok()?;
        // 检查该行是否包含目标库名
        if line.contains(lib_name) && result.is_none() {
            // 格式: 7f1234560000-7f1234570000 r-xp 00000000 08:01 12345 /path/to/lib.so
            let addr_part = line.split('-').next()?;
            let base = usize::from_str_radix(addr_part, 16).ok()?;
            result = Some(base);
        }

        // if line.contains("memfd") || line.contains("apex") {
        //     let mut lines = line.split('-');
        //     let base_addr = lines.next()?;
        //     let end_addr = lines.next()?.split(' ').next()?;
        //     let base = usize::from_str_radix(base_addr, 16).ok()?;
        //     let end = usize::from_str_radix(end_addr, 16).ok()?;
        //     stalker.exclude(&MemoryRange::new(NativePointer(base as *mut c_void), end - base));
        // }
    }
    result
}

pub extern "C" fn replacecb(arg1:usize) -> usize {
    log_msg("start !".to_string());
    // get_interceptor().revert(NativePointer(GLOBAL_TARGET.get().unwrap().clone() as *mut c_void));


    // 调用原始函数
    let original = *GLOBAL_ORIGINAL.get().unwrap();
    let original_fn: extern "C" fn(usize) -> usize = unsafe {
        std::mem::transmute(original)
    };
    // follow(0);
    original_fn(arg1)
}

pub extern "C" fn replacecc(){
    log_msg("stop !".to_string());
    // get_interceptor().revert(NativePointer(GLOBAL_TARGET.get().unwrap().clone() as *mut c_void));
    // follow(0);
    get_stalker().stop();
}

impl ProbeListener for plistener {
    fn on_hit(&mut self, context: InvocationContext) {
        log_msg("hooked !".to_string());
        follow(context.thread_id() as usize);
        // get_interceptor().revert(NativePointer(GLOBAL_TARGET.get().unwrap().clone() as *mut c_void));
    }
}

struct blistener;
impl ProbeListener for blistener {
    fn on_hit(&mut self, context: InvocationContext) {
        log_msg("follow stopd!".to_string());
        get_stalker().unfollow(context.thread_id() as usize);
        get_stalker().garbage_collect();
        get_stalker().flush();
    }
}

pub fn hfollow(lib:&str,addr:usize) {
    // let base = find_lib_base(lib).expect(&format!("Failed to find {} in /proc/self/maps", lib));
    let base = Process::obtain(&GUM).find_module_by_name(lib).unwrap().range().base_address().0 as usize;
    // let base = Process::obtain(&GUM).find_module_by_name(lib).unwrap().range().base_address().0 as usize;
    let target = base + addr;
    let _ = GLOBAL_TARGET.set(target);
    // let mut listener = OpenListener {};
    let mut interceptor = Interceptor::obtain(&GUM);
    log_msg(format!("begin trace {:x}",target));
    // interceptor.attach(NativePointer(target as *mut c_void),&mut listener).unwrap();
    match interceptor.replace(NativePointer(target as *mut c_void),NativePointer(replacecb as *mut c_void),NativePointer(null_mut())) {
        Ok(original) => {
            let _ = GLOBAL_ORIGINAL.set(original.0 as usize);
            log_msg(format!("replace success, original trampoline: {:x}", original.0 as usize));
        }
        Err(e) => {
            log_msg(format!("replace failed: {:?}", e));
        }
    }
    // interceptor.replace(NativePointer((base+0x320BC4) as *mut c_void),NativePointer(replacecc as *mut c_void),NativePointer(null_mut()));
    // interceptor.attach_instruction(NativePointer(target as *mut c_void),&mut plistener);
    // interceptor.attach_instruction(NativePointer((base+0x320BC4) as *mut c_void),&mut blistener);
    ()

}

// JNI 函数签名: (JNIEnv*, jobject/jclass) -> 返回值
pub extern "C" fn replaceq(jenv: RWord, jobj: RWord) -> RWord {
    get_interceptor().revert(NativePointer(GLOBAL_TARGET.get().unwrap().clone() as *mut c_void));
    log_msg(format!("replaceq: arg1=0x{:x}, arg2=0x{:x}\n", jenv, jobj));
    let value:u64;
    unsafe {
        core::arch::asm!(
        "mrs {0}, tpidr_el0",
        out(reg) value,
        options(nomem, nostack, preserves_flags),
        );
    }
    log_msg(format!("tls=0x{:x}", value));
    // start_dump_mem();

    // 使用在 qfollow 中初始化的全局 VM
    let vm = get_vm();
    let target = GLOBAL_TARGET.get().unwrap().clone() as u64;

    let state = vm.gpr_state().expect("GPRState is null");
    let _stack = VirtualStack::new(state, 0x100000).unwrap();
    log_msg(format!("SP=0x{:x}\n", _stack.alloc.ptr as u64 + 0x100000));
    // JNI 函数需要两个参数: JNIEnv* 和 jobject/jclass
    match vm.call(target as RWord, &[jenv, jobj]) {
        Some(ret) => {
            log_msg(format!("QBDI call succeeded, ret=0x{:x}", ret));
            ret
        }
        None => {
            log_msg("QBDI vm.call() failed, trying vm.run()...".to_string());

            // 方法2: 使用 run() 手动设置寄存器
            let state = vm.gpr_state().unwrap();
            state.x0 = jenv;   // 第一个参数: JNIEnv*
            state.x1 = jobj;   // 第二个参数: jobject/jclass
            state.lr = 0;      // 返回地址设为 0

            let success = vm.run(target as RWord, 0);
            log_msg(format!("vm.run() returned: {}", success));

            if success {
                let ret = vm.gpr_state().unwrap().x0;
                log_msg(format!("run succeeded, ret=0x{:x}", ret));
                ret
            } else {
                log_msg("QBDI vm.run() also failed, calling original".to_string());
                let orig: extern "C" fn(RWord, RWord) -> RWord = unsafe {
                    std::mem::transmute(*GLOBAL_ORIGINAL.get().unwrap())
                };
                orig(jenv, jobj)
            }
        }
    }
}

// VM 事件回调 - 用于调试
extern "C" fn vm_event_cb(
    _vm: VMInstanceRef,
    event: *const qbdi::ffi::VMState,
    _gpr: *mut GPRState,
    _fpr: *mut FPRState,
    _data: *mut c_void,
) -> VMAction {
    unsafe {
        if !event.is_null() {
            let ev = &*event;
            log_msg(format!("VM Event: event={}, seq_start=0x{:x}, seq_end=0x{:x}",
                ev.event, ev.sequenceStart, ev.sequenceEnd));
        }
    }
    VMAction_QBDI_CONTINUE
}

extern "C" fn mem_acc_cb(
    _vm: VMInstanceRef,
    _gpr: *mut GPRState,
    _fpr: *mut FPRState,
    _data: *mut c_void,
) -> VMAction {
    unsafe {
        let accesses = VMRef::from_raw(_vm).get_inst_memory_access();
        for acc in accesses {
            // 只处理读取操作
            if !acc.is_read() {
                continue;
            }

            let inst_addr = acc.inst_address();
            let access_addr = acc.access_address();
            let value = acc.value();
            let size = acc.size() as u32;

            // 创建并发送内存访问记录
            let mem_acc = MemAccess {
                inst_addr,
                access_addr,
                value,
                size,
            };

            // 发送到后台线程保存
            let _ = MEM_ACCESS_SENDER.try_send(mem_acc);
        }
    }
    VMAction_QBDI_CONTINUE
}

/// EXEC_TRANSFER_RETURN 事件回调
/// 当从外部代码（如 libc）返回到 instrumented 代码时触发
/// 此时可以捕获外部调用的返回值（x0）
extern "C" fn exec_transfer_return_cb(
    _vm: VMInstanceRef,
    event: *const qbdi::ffi::VMState,
    gpr: *mut GPRState,
    _fpr: *mut FPRState,
    _data: *mut c_void,
) -> VMAction {
    unsafe {
        if event.is_null() || gpr.is_null() {
            return VMAction_QBDI_CONTINUE;
        }

        // sequenceStart 是返回后即将执行的指令地址
        let return_addr = (*gpr).pc;
        // let return_addr = gpr_state.pc;
        // x0 包含外部调用的返回值
        let return_value = (*gpr).x0;
        // log_msg(format!("QBDI call returned: 0x{:x}", return_addr));

        // 创建并发送外部返回记录
        let ext_ret = ExternalReturn {
            return_addr,
            return_value,
        };

        // 发送到后台线程保存
        let _ = EXTERNAL_RETURN_SENDER.try_send(ext_ret);
    }
    VMAction_QBDI_CONTINUE
}

pub extern "C" fn qbdicb(
    _vm: VMInstanceRef,
    gpr_state: *mut GPRState,
    _fpr_state: *mut FPRState,
    _data: *mut c_void,
) -> VMAction {
    unsafe {
        let addr = (*gpr_state).pc;
        // log_msg(format!("inst: 0x{:x} 0x{:x}\n", addr,(*gpr_state).sp));
        // 发送地址到后台线程保存
        let _ = QBDI_ADDR_SENDER.send(addr);
    }
    VMAction_QBDI_CONTINUE
}

/// 获取全局 QBDI VM 的可变引用
#[inline]
fn get_vm() -> &'static mut VM {
    let cell = GLOBAL_VM.get().expect("QBDI VM not initialized");
    unsafe { &mut *cell.0.get() }
}

pub fn qfollow(lib:&str,addr:usize) {
    let md = Process::obtain(&GUM).find_module_by_name(lib).unwrap();
    let base = md.range().base_address().0 as usize;
    let end = base + md.range().size();
    let target = base + addr;
    let _ = GLOBAL_TARGET.set(target);
    log_msg(format!("base:0x{:x}\n",base));
    log_msg(format!("target:0x{:x}\n", target));

    // 初始化 QBDI VM
    let mut vm = VM::new();

    // let state = vm.gpr_state().expect("GPRState is null");
    // let _stack = VirtualStack::new(state, 0x100000).unwrap();
    // log_msg(format!("SP=0x{:x}\n", _stack.alloc.ptr as u64));
    // 设置 instrumented range
    vm.add_instrumented_range(base as RWord, end as RWord);

    // 添加指令回调
    vm.add_code_cb(InstPosition_QBDI_PREINST, Some(qbdicb), null_mut(), 0);
    vm.add_mem_access_cb(MemoryAccessType_QBDI_MEMORY_READ, Some(mem_acc_cb), null_mut(), 0);
    // 添加外部调用返回事件回调，用于捕获 libc 等外部函数的返回值
    vm.add_vm_event_cb(VMEvent_QBDI_EXEC_TRANSFER_RETURN, Some(exec_transfer_return_cb), null_mut());


    // 存储 VM 到全局变量
    let _ = GLOBAL_VM.set(VMCell(UnsafeCell::new(vm)));
    // log_msg("QBDI VM initialized and stored globally".to_string());

    let interceptor = get_interceptor();
    match interceptor.replace(NativePointer(target as *mut c_void), NativePointer(replaceq as *mut c_void), NativePointer(null_mut())) {
        Ok(original) => {
            let _ = GLOBAL_ORIGINAL.set(original.0 as usize);
            // log_msg(format!("replace success, original trampoline: {:x}", original.0 as usize));
        }
        Err(e) => {
            log_msg(format!("replace failed: {:?}", e));
        }
    }
}



