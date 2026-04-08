/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * KPM-based Dynamic Library (.so) Monitor (KernelPatch NATIVE API)
 * Requires ZERO external kernel headers!
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
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
#define LDMON_NL_VERSION 1
#define LDMON_NL_MSG_SUBSCRIBE 0
#define LDMON_NL_MSG_EVENT_DLOPEN 1
#define LDMON_NL_MSG_UNSUBSCRIBE 255
#define LDMON_NL_PROTO_PRIMARY 31
#define LDMON_NL_PROTO_FALLBACK 30

struct ldm_nl_event {
    u32 version;
    u32 msg_type;
    u32 pid;
    u32 uid;
    u32 path_len;
    u32 reserved;
    char path[MAX_PATH_LEN];
};

struct net;
struct mutex;
struct sk_buff;
struct sock;

struct nlmsghdr {
    u32 nlmsg_len;
    u16 nlmsg_type;
    u16 nlmsg_flags;
    u32 nlmsg_seq;
    u32 nlmsg_pid;
};

struct netlink_kernel_cfg {
    unsigned int groups;
    unsigned int flags;
    void (*input)(struct sk_buff *skb);
    struct mutex *cb_mutex;
    int (*bind)(struct net *net, int group);
    void (*unbind)(struct net *net, int group);
    bool (*compare)(struct net *net, struct sock *sk);
};

#define NLMSG_DONE 0x3
#define MSG_DONTWAIT 0x40
#define GFP_ATOMIC 0
#define pr_debug pr_info

static struct net *kv_init_net = NULL;
static struct sock *(*kf_netlink_kernel_create)(struct net *net, int unit, struct netlink_kernel_cfg *cfg) = NULL;
static void (*kf_netlink_kernel_release)(struct sock *sk) = NULL;
static int (*kf_netlink_unicast)(struct sock *ssk, struct sk_buff *skb, u32 portid, int nonblock) = NULL;
static struct sk_buff *(*kf_alloc_skb)(unsigned int size, gfp_t priority) = NULL;
static void (*kf_kfree_skb)(struct sk_buff *skb) = NULL;
static void *(*kf_skb_put)(struct sk_buff *skb, unsigned int len) = NULL;
static int (*kf_skb_copy_bits)(const struct sk_buff *skb, int offset, void *to, int len) = NULL;

static struct sock *ldm_nl_sock = NULL;
static u32 subscriber_portid = 0;
static int ldm_nl_protocol = 0;
static bool monitor_enabled = false;
static char monitor_filter[MAX_PATH_LEN] = {0};
static u32 monitor_target_pid = 0;
static bool monitor_netlink_ready = false;
static const char *monitor_backend_name = "logonly";

static int ldm_nl_resolve_symbols(void)
{
    kv_init_net = (struct net *)kallsyms_lookup_name("init_net");
    kf_netlink_kernel_create =
        (typeof(kf_netlink_kernel_create))kallsyms_lookup_name("netlink_kernel_create");
    kf_netlink_kernel_release =
        (typeof(kf_netlink_kernel_release))kallsyms_lookup_name("netlink_kernel_release");
    kf_netlink_unicast =
        (typeof(kf_netlink_unicast))kallsyms_lookup_name("netlink_unicast");
    kf_alloc_skb = (typeof(kf_alloc_skb))kallsyms_lookup_name("alloc_skb");
    kf_kfree_skb = (typeof(kf_kfree_skb))kallsyms_lookup_name("kfree_skb");
    kf_skb_put = (typeof(kf_skb_put))kallsyms_lookup_name("skb_put");
    kf_skb_copy_bits = (typeof(kf_skb_copy_bits))kallsyms_lookup_name("skb_copy_bits");

    if (!kv_init_net || !kf_netlink_kernel_create || !kf_netlink_kernel_release || !kf_netlink_unicast ||
        !kf_alloc_skb || !kf_kfree_skb || !kf_skb_put || !kf_skb_copy_bits) {
        pr_err("[KPM-DLOPEN] resolve symbols failed: init_net=%p netlink_create=%p netlink_release=%p "
               "netlink_unicast=%p alloc_skb=%p kfree_skb=%p skb_put=%p skb_copy_bits=%p\n",
               kv_init_net, kf_netlink_kernel_create, kf_netlink_kernel_release, kf_netlink_unicast,
               kf_alloc_skb, kf_kfree_skb, kf_skb_put, kf_skb_copy_bits);
        return -2;
    }

    return 0;
}

static void ldm_nl_clear_subscriber(u32 portid)
{
    if (subscriber_portid == portid) {
        subscriber_portid = 0;
    }
}

static void ldm_nl_recv(struct sk_buff *skb)
{
    struct nlmsghdr nlh;
    struct ldm_nl_event msg;
    u32 portid;

    if (!skb) {
        return;
    }

    if (kf_skb_copy_bits(skb, 0, &nlh, sizeof(nlh)) < 0) {
        return;
    }

    if (nlh.nlmsg_len < sizeof(struct nlmsghdr) + sizeof(struct ldm_nl_event)) {
        return;
    }

    if (kf_skb_copy_bits(skb, sizeof(struct nlmsghdr), &msg, sizeof(msg)) < 0) {
        return;
    }

    if (msg.version != LDMON_NL_VERSION) {
        return;
    }

    portid = nlh.nlmsg_pid;

    if (msg.msg_type == LDMON_NL_MSG_SUBSCRIBE) {
        if (subscriber_portid && subscriber_portid != portid) {
            pr_warn("[KPM-DLOPEN] replacing netlink subscriber %u -> %u\n",
                    subscriber_portid, portid);
        }
        subscriber_portid = portid;
        pr_info("[KPM-DLOPEN] netlink subscribed: proto=%d portid=%u\n",
                ldm_nl_protocol, subscriber_portid);
    } else if (msg.msg_type == LDMON_NL_MSG_UNSUBSCRIBE) {
        ldm_nl_clear_subscriber(portid);
        pr_info("[KPM-DLOPEN] netlink unsubscribed: %u\n", portid);
    }
}

static void ldm_nl_send_event(pid_t pid, uid_t uid, const char *path, u32 path_len)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    struct ldm_nl_event *msg;
    u32 copy_len;
    u32 total_len;
    int ret;

    if (!monitor_netlink_ready || !ldm_nl_sock || subscriber_portid == 0 || !path) {
        return;
    }

    copy_len = path_len;
    if (copy_len >= MAX_PATH_LEN) {
        copy_len = MAX_PATH_LEN - 1;
    }

    total_len = sizeof(struct nlmsghdr) + sizeof(struct ldm_nl_event);
    skb = kf_alloc_skb(total_len, GFP_ATOMIC);
    if (!skb) {
        return;
    }

    nlh = kf_skb_put(skb, total_len);
    if (!nlh) {
        kf_kfree_skb(skb);
        return;
    }

    memset(nlh, 0, total_len);
    nlh->nlmsg_len = total_len;
    nlh->nlmsg_type = NLMSG_DONE;
    nlh->nlmsg_pid = 0;

    msg = (struct ldm_nl_event *)(nlh + 1);
    memset(msg, 0, sizeof(*msg));
    msg->version = LDMON_NL_VERSION;
    msg->msg_type = LDMON_NL_MSG_EVENT_DLOPEN;
    msg->pid = pid;
    msg->uid = uid;
    msg->path_len = copy_len;
    memcpy(msg->path, path, copy_len);
    msg->path[copy_len] = '\0';

    ret = kf_netlink_unicast(ldm_nl_sock, skb, subscriber_portid, MSG_DONTWAIT);
    if (ret < 0) {
        pr_warn("[KPM-DLOPEN] netlink send failed: proto=%d portid=%u ret=%d\n",
                ldm_nl_protocol, subscriber_portid, ret);
        subscriber_portid = 0;
    }
}

static bool path_matches_filter(const char *path)
{
    if (!monitor_filter[0]) {
        return true;
    }
    return strstr(path, monitor_filter) != NULL;
}

static bool parse_u32_arg(const char *value, u32 *out)
{
    unsigned long acc = 0;
    char ch;

    if (!value || !*value) {
        return false;
    }

    while ((ch = *value++) != '\0') {
        if (ch < '0' || ch > '9') {
            return false;
        }
        acc = acc * 10 + (unsigned long)(ch - '0');
        if (acc > 0xffffffffUL) {
            return false;
        }
    }

    if (acc == 0) {
        return false;
    }

    *out = (u32)acc;
    return true;
}

static long monitor_control0(const char *args, char *__user out_msg, int outlen)
{
    char status[160] = {0};
    u32 parsed_pid = 0;

    if (!args || !*args) {
        return -22;
    }

    if (!strcmp(args, "start")) {
        monitor_enabled = true;
        pr_info("[KPM-DLOPEN] ctl0 start\n");
    } else if (!strcmp(args, "stop")) {
        monitor_enabled = false;
        pr_info("[KPM-DLOPEN] ctl0 stop\n");
    } else if (!strcmp(args, "clear-filter")) {
        monitor_filter[0] = '\0';
        pr_info("[KPM-DLOPEN] ctl0 clear-filter\n");
    } else if (!strcmp(args, "clear-target-pid")) {
        monitor_target_pid = 0;
        pr_info("[KPM-DLOPEN] ctl0 clear-target-pid\n");
    } else if (!strncmp(args, "filter=", 7)) {
        strncpy(monitor_filter, args + 7, MAX_PATH_LEN - 1);
        monitor_filter[MAX_PATH_LEN - 1] = '\0';
        pr_info("[KPM-DLOPEN] ctl0 filter=%s\n", monitor_filter);
    } else if (!strncmp(args, "target-pid=", 11)) {
        if (!parse_u32_arg(args + 11, &parsed_pid)) {
            pr_warn("[KPM-DLOPEN] ctl0 invalid target pid args=%s\n", args);
            return -22;
        }
        monitor_target_pid = parsed_pid;
        pr_info("[KPM-DLOPEN] ctl0 target-pid=%u\n", monitor_target_pid);
    } else if (strcmp(args, "status")) {
        pr_warn("[KPM-DLOPEN] ctl0 unknown args=%s\n", args);
        return -22;
    }

    if (out_msg && outlen > 0) {
        snprintf(status,
                 sizeof(status),
                 "enabled=%u filter=%s target_pid=%u backend=%s netlink_proto=%d subscriber=%u\n",
                 monitor_enabled ? 1 : 0,
                 monitor_filter[0] ? monitor_filter : "<none>",
                 monitor_target_pid,
                 monitor_backend_name,
                 ldm_nl_protocol,
                 subscriber_portid);
        compat_copy_to_user(out_msg, status, strnlen(status, sizeof(status)));
    }

    return 0;
}

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

    pid = raw_syscall0(172); // __NR_getpid

    if (monitor_target_pid != 0 && (u32)pid != monitor_target_pid) {
        return;
    }

    /* Filter out Android system and root processes (typically < 10000) */
    if (uid < 10000) {
        return;
    }

    if (!monitor_enabled) {
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
    if (len > 3 && path[len-3] == '.' && path[len-2] == 's' && path[len-1] == 'o' && path_matches_filter(path)) {
        ldm_nl_send_event(pid, uid, path, len);
        pr_debug("[KPM-DLOPEN] | PID:%d | UID:%u | PATH:%s\n", pid, uid, path);
    }
}

/**
 * @brief module initialization
 */
static long monitor_init(const char *args, const char *event, void *__user reserved)
{
    struct netlink_kernel_cfg cfg = {
        .input = ldm_nl_recv,
    };
    int rc;
    int hook_rc1;
    int hook_rc2;

    pr_info("[KPM-DLOPEN] init, registering KernelPatch Syscall Hooks\n");

    /* 
     * Hook Native Syscalls using KernelPatch's headerless API!
     * 56 = __NR_openat
     * 437 = __NR_openat2
     */
    hook_rc1 = hook_syscalln(56, 4, handler_before, NULL, NULL);
    hook_rc2 = hook_syscalln(437, 4, handler_before, NULL, NULL);
    if (hook_rc1 != 0 || hook_rc2 != 0) {
        pr_err("[KPM-DLOPEN] failed to register syscall hooks: openat=%d openat2=%d\n", hook_rc1, hook_rc2);
        if (hook_rc1 == 0) {
            unhook_syscalln(56, handler_before, NULL);
        }
        if (hook_rc2 == 0) {
            unhook_syscalln(437, handler_before, NULL);
        }
        monitor_backend_name = "disabled";
        return -1;
    }

    monitor_backend_name = "logonly";
    monitor_enabled = false;
    monitor_netlink_ready = false;
    ldm_nl_protocol = 0;

    rc = ldm_nl_resolve_symbols();
    if (rc == 0) {
        ldm_nl_sock = kf_netlink_kernel_create(kv_init_net, LDMON_NL_PROTO_PRIMARY, &cfg);
        if (ldm_nl_sock) {
            ldm_nl_protocol = LDMON_NL_PROTO_PRIMARY;
        } else {
            ldm_nl_sock = kf_netlink_kernel_create(kv_init_net, LDMON_NL_PROTO_FALLBACK, &cfg);
            if (ldm_nl_sock) {
                ldm_nl_protocol = LDMON_NL_PROTO_FALLBACK;
            }
        }

        if (ldm_nl_sock) {
            monitor_netlink_ready = true;
            monitor_backend_name = "netlink";
            pr_info("[KPM-DLOPEN] netlink backend enabled: proto=%d\n", ldm_nl_protocol);
        } else {
            pr_warn("[KPM-DLOPEN] netlink socket unavailable, falling back to logonly backend\n");
        }
    } else {
        pr_warn("[KPM-DLOPEN] netlink symbols unavailable, falling back to logonly backend\n");
    }

    pr_info("[KPM-DLOPEN] Syscall Native Hooks Registered. backend=%s\n", monitor_backend_name);
    return 0;
}

static long monitor_exit(void *__user reserved)
{
    unhook_syscalln(56, handler_before, NULL);
    unhook_syscalln(437, handler_before, NULL);

    subscriber_portid = 0;
    monitor_enabled = false;
    monitor_netlink_ready = false;
    if (ldm_nl_sock) {
        kf_netlink_kernel_release(ldm_nl_sock);
        ldm_nl_sock = NULL;
    }
    ldm_nl_protocol = 0;
    monitor_backend_name = "logonly";

    pr_info("[KPM-DLOPEN] Syscall Hooks unregistered. Module exited.\n");
    return 0;
}

KPM_INIT(monitor_init);
KPM_CTL0(monitor_control0);
KPM_EXIT(monitor_exit);
