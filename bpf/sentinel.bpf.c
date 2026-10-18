// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "sentinel.h"

char LICENSE[] SEC("license") = "GPL";

/* Open flags constants */
#define O_WRONLY    00000001
#define O_RDWR      00000002
#define O_CREAT     00000100
#define O_TRUNC     00001000

/* AF_INET */
#define AF_INET     2
#define AF_INET6    10

/* Minimal sockaddr structure for IPv4 parsing */
struct sockaddr_in_bpf {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr;
};

/* Ring buffer map: 16 MB capacity */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");

/* Per-CPU drop counter */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drops SEC(".maps");

/* Ignored PIDs (e.g. sentinel daemon self-filtering) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} ignored_pids SEC(".maps");

/* Reserve and zero memory in ring buffer */
static __always_inline struct event *reserve_event(void) {
    __u32 key = 0;
    struct event *ev = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!ev) {
        __u64 *drop_cnt = bpf_map_lookup_elem(&drops, &key);
        if (drop_cnt) {
            *drop_cnt += 1;
        }
        return 0;
    }
    __builtin_memset(ev, 0, sizeof(*ev));
    return ev;
}

/* Fast check if current PID should be ignored */
static __always_inline int is_ignored_pid(__u32 pid) {
    __u8 *val = bpf_map_lookup_elem(&ignored_pids, &pid);
    return val != 0;
}

/* Helper to populate common process metadata */
static __always_inline void fill_common_metadata(struct event *ev, struct task_struct *task, __u64 pid_tgid) {
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->cgroup_id = bpf_get_current_cgroup_id();
    ev->pid = pid_tgid >> 32;
    ev->tid = (__u32)pid_tgid;

    __u64 uid_gid = bpf_get_current_uid_gid();
    ev->uid = (__u32)uid_gid;
    ev->gid = uid_gid >> 32;

    if (task) {
        ev->ppid = BPF_CORE_READ(task, real_parent, tgid);
        ev->euid = BPF_CORE_READ(task, cred, euid.val);
        ev->egid = BPF_CORE_READ(task, cred, egid.val);
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        if (parent) {
            bpf_probe_read_kernel_str(ev->pcomm, sizeof(ev->pcomm), &parent->comm);
        }
    }

    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
}

/*
 * HOOK 1: Process Execution
 * Tracepoint: sched/sched_process_exec
 */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(trace_sched_process_exec, struct task_struct *task, pid_t old_pid, struct linux_binprm *bprm) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (is_ignored_pid(pid))
        return 0;

    struct event *ev = reserve_event();
    if (!ev)
        return 0;

    ev->event_type = EVENT_EXEC;
    fill_common_metadata(ev, task, pid_tgid);

    if (bprm) {
        const char *filename = BPF_CORE_READ(bprm, filename);
        if (filename) {
            bpf_probe_read_kernel_str(ev->path, sizeof(ev->path), filename);
        }
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/*
 * HOOK 2: Process Exit
 * Tracepoint: sched/sched_process_exit
 */
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (is_ignored_pid(pid))
        return 0;

    struct event *ev = reserve_event();
    if (!ev)
        return 0;

    ev->event_type = EVENT_EXIT;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    fill_common_metadata(ev, task, pid_tgid);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/*
 * HOOK 3: Process Fork / Clone
 * Tracepoint: sched/sched_process_fork
 */
SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 parent_pid = ctx->parent_pid;
    __u32 child_pid = ctx->child_pid;

    if (is_ignored_pid(parent_pid))
        return 0;

    struct event *ev = reserve_event();
    if (!ev)
        return 0;

    ev->event_type = EVENT_FORK;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    fill_common_metadata(ev, task, pid_tgid);

    ev->ppid = parent_pid;
    ev->newfd = child_pid; // Carry child PID in newfd field

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/*
 * HOOK 4: File Open / Create / Truncate
 * Tracepoint: syscalls/sys_enter_openat
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (is_ignored_pid(pid))
        return 0;

    __u64 flags = ctx->args[2];
    /* Kernel filtering: only track write/create modifications to reduce noise */
    if (!(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)))
        return 0;

    struct event *ev = reserve_event();
    if (!ev)
        return 0;

    ev->event_type = EVENT_OPENAT;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    fill_common_metadata(ev, task, pid_tgid);

    ev->flags = flags;
    const char *pathname = (const char *)ctx->args[1];
    if (pathname) {
        bpf_probe_read_user_str(ev->path, sizeof(ev->path), pathname);
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/*
 * HOOK 5: Network Socket Connect
 * Tracepoint: syscalls/sys_enter_connect
 */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (is_ignored_pid(pid))
        return 0;

    struct event *ev = reserve_event();
    if (!ev)
        return 0;

    ev->event_type = EVENT_CONNECT;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    fill_common_metadata(ev, task, pid_tgid);

    ev->fd = ctx->args[0];
    struct sockaddr_in_bpf sa = {};
    const void *sockaddr_ptr = (const void *)ctx->args[1];
    if (sockaddr_ptr) {
        bpf_probe_read_user(&sa, sizeof(sa), sockaddr_ptr);
        ev->family = sa.sin_family;
        if (sa.sin_family == AF_INET) {
            ev->daddr = sa.sin_addr;
            ev->dport = __builtin_bswap16(sa.sin_port);
        }
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/*
 * HOOK 6: Descriptor Duplication (dup2 / dup3)
 * Tracepoints: syscalls/sys_enter_dup2, syscalls/sys_enter_dup3
 */
SEC("tracepoint/syscalls/sys_enter_dup2")
int trace_sys_enter_dup2(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (is_ignored_pid(pid))
        return 0;

    __u32 newfd = ctx->args[1];
    /* Kernel filtering: only track dup to standard I/O (stdin=0, stdout=1, stderr=2) */
    if (newfd > 2)
        return 0;

    struct event *ev = reserve_event();
    if (!ev)
        return 0;

    ev->event_type = EVENT_DUP;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    fill_common_metadata(ev, task, pid_tgid);

    ev->oldfd = ctx->args[0];
    ev->newfd = newfd;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int trace_sys_enter_dup3(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (is_ignored_pid(pid))
        return 0;

    __u32 newfd = ctx->args[1];
    if (newfd > 2)
        return 0;

    struct event *ev = reserve_event();
    if (!ev)
        return 0;

    ev->event_type = EVENT_DUP;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    fill_common_metadata(ev, task, pid_tgid);

    ev->oldfd = ctx->args[0];
    ev->newfd = newfd;
    ev->flags = ctx->args[2];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/*
 * HOOK 7: Process Tracing / Injection (ptrace)
 * Tracepoint: syscalls/sys_enter_ptrace
 */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_sys_enter_ptrace(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (is_ignored_pid(pid))
        return 0;

    struct event *ev = reserve_event();
    if (!ev)
        return 0;

    ev->event_type = EVENT_PTRACE;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    fill_common_metadata(ev, task, pid_tgid);

    ev->flags = ctx->args[0]; // ptrace request
    ev->newfd = ctx->args[1]; // target pid

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/*
 * HOOK 8: Filesystem Mount
 * Tracepoint: syscalls/sys_enter_mount
 */
SEC("tracepoint/syscalls/sys_enter_mount")
int trace_sys_enter_mount(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (is_ignored_pid(pid))
        return 0;

    struct event *ev = reserve_event();
    if (!ev)
        return 0;

    ev->event_type = EVENT_MOUNT;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    fill_common_metadata(ev, task, pid_tgid);

    const char *dev = (const char *)ctx->args[0];
    const char *dir = (const char *)ctx->args[1];
    if (dir) {
        bpf_probe_read_user_str(ev->path, sizeof(ev->path), dir);
    }
    if (dev) {
        bpf_probe_read_user_str(ev->extra, sizeof(ev->extra), dev);
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/*
 * HOOK 9: Privilege Escalation (setuid / setresuid)
 * Tracepoint: syscalls/sys_enter_setuid
 */
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_sys_enter_setuid(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (is_ignored_pid(pid))
        return 0;

    struct event *ev = reserve_event();
    if (!ev)
        return 0;

    ev->event_type = EVENT_SETUID;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    fill_common_metadata(ev, task, pid_tgid);

    ev->retval = ctx->args[0]; // requested uid

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
