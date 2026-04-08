#include "aliuhook.h"
#include <dobby.h>
#include <sys/mman.h>
#include <bits/sysconf.h>
#include <cstdlib>
#include <cerrno>
#include "log.h"

// 定义 AliuHook 类的静态成员变量
int AliuHook::android_version = -1;
pine::ElfImg AliuHook::elf_img; // NOLINT(cert-err58-cpp)

// 初始化函数
void AliuHook::init(int version) {
    elf_img.Init("libart.so", version);
    android_version = version;
}

static size_t page_size_;

// Macros to align addresses to page boundaries
#define ALIGN_DOWN(addr, page_size)         ((addr) & -(page_size))
#define ALIGN_UP(addr, page_size)           (((addr) + ((page_size) - 1)) & ~((page_size) - 1))

// 内存保护函数
static bool Unprotect(void *addr) {
    auto addr_uint = reinterpret_cast<uintptr_t>(addr);
    auto page_aligned_prt = reinterpret_cast<void *>(ALIGN_DOWN(addr_uint, page_size_));
    size_t size = page_size_;
    if (ALIGN_UP(addr_uint + page_size_, page_size_) != ALIGN_UP(addr_uint, page_size_)) {
        size += page_size_;
    }

    int result = mprotect(page_aligned_prt, size, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (result == -1) {
        LOGE("mprotect failed for %p: %s (%d)", addr, strerror(errno), errno);
        return false;
    }
    return true;
}

// InlineHooker 实现
void *InlineHooker(void *address, void *replacement) {
    if (!Unprotect(address)) {
        return nullptr;
    }

    void *origin_call;
    if (DobbyHook(address, (dobby_dummy_func_t)replacement, (dobby_dummy_func_t *)&origin_call) == 0) {
        return origin_call;
    } else {
        return nullptr;
    }
}

// InlineUnhooker 实现
bool InlineUnhooker(void *func) {
    return DobbyDestroy(func) == RT_SUCCESS;
}