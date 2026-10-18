#ifndef __SENTINEL_H__
#define __SENTINEL_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

/* Event Types */
enum event_type {
    EVENT_UNKNOWN = 0,
    EVENT_EXEC    = 1,
    EVENT_EXIT    = 2,
    EVENT_FORK    = 3,
    EVENT_OPENAT  = 4,
    EVENT_CONNECT = 5,
    EVENT_DUP     = 6,
    EVENT_PTRACE  = 7,
    EVENT_MOUNT   = 8,
    EVENT_SETUID  = 9,
};

/*
 * Event struct: strictly 480 bytes, 8-byte aligned, no implicit padding.
 * 64-bit ints first, then 32-bit, 16-bit, and byte arrays.
 */
struct event {
    /* 64-bit fields (40 bytes) */
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u64 event_type;
    __u64 retval;
    __u64 flags;

    /* 32-bit fields (40 bytes) */
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 euid;
    __u32 egid;
    __u32 fd;
    __u32 oldfd;
    __u32 newfd;

    /* Network fields (16 bytes) */
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;

    /* Buffers (384 bytes) */
    char comm[16];
    char pcomm[16];
    char path[256];
    char extra[96];
};

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct event) == 480, "struct event must be exactly 480 bytes");
#endif

#endif /* __SENTINEL_H__ */
