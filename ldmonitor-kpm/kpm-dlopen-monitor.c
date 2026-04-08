/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * KPM-based Dynamic Library (.so) Monitor (KernelPatch NATIVE API)
 * Requires ZERO external kernel headers!
 */

#include <compiler.h>
#include <kpmodule.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <taskext.h>

/* Use KernelPatch native syscall hooking instead of kprobes */
#include <syscall.h>

///< The name of the module, each KPM must has a unique name.
KPM_NAME("kpm-dlopen-monitor");

///< The version of the module.
KPM_VERSION("1.0.0");

///< The license type.
KPM_LICENSE("GPL v2");

///< The author.
KPM_AUTHOR("Antigravity");

///< The description.
KPM_DESCRIPTION("KernelPatch Module for stealth .so loading monitoring (Headerless Hook)");

#define MAX_PATH_LEN 256

/**
 * @brief Hook pre-handler for openat/openat2 syscalls
 */
static void handler_before(hook_fargs4_t *args, void *udata)
{
    uid_t uid;
    pid_t pid;
    char path[MAX_PATH_LEN] = {0};
    int len;
    const char __user *filename;

    /* Get the user ID of the calling process via kputils */
    uid = current_uid();

    /* Filter out Android system and root processes (typically < 10000) */
    if (uid < 10000) {
        return;
    }

    /* 
     * In sys_openat(dfd, filename, flags, mode)
     * In sys_openat2(dfd, filename, how, size)
     * Both have `filename` as the second argument (arg1)
     */
    filename = (const char __user *)syscall_argn(args, 1);

    if (!filename) {
        return;
    }

    /* Safely copy the user-space string using KernelPatch native compat API */
    compat_strncpy_from_user(path, filename, MAX_PATH_LEN - 1);
    len = strnlen(path, MAX_PATH_LEN);
        
    /* Filter logic: Only monitor files ending in ".so" */
    if (len > 3 && path[len-3] == '.' && path[len-2] == 's' && path[len-1] == 'o') {
        pid = raw_syscall0(172); // __NR_getpid
        pr_info("[KPM-DLOPEN] | PID:%d | UID:%u | PATH:%s\n", pid, uid, path);
    }
}

/**
 * @brief module initialization
 */
static long monitor_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("[KPM-DLOPEN] init, registering KernelPatch Syscall Hooks\n");
    
    /* 
     * Hook Native Syscalls using KernelPatch's headerless API!
     * 56 = __NR_openat
     * 437 = __NR_openat2
     */
    hook_syscalln(56, 4, handler_before, NULL, NULL);
    hook_syscalln(437, 4, handler_before, NULL, NULL);
    
    pr_info("[KPM-DLOPEN] Syscall Native Hooks Registered. Stealth .so monitoring is Active!\n");
    return 0;
}

static long monitor_exit(void *__user reserved)
{
    unhook_syscalln(56, handler_before, NULL);
    unhook_syscalln(437, handler_before, NULL);
    pr_info("[KPM-DLOPEN] Syscall Hooks unregistered. Module exited.\n");
    return 0;
}

KPM_INIT(monitor_init);
KPM_EXIT(monitor_exit);
