// SPDX-License-Identifier: GPL-2.0
//
// 网络连接追踪 BPF 程序
//
// 功能：
//   - 追踪 TCP 连接建立（入站 / 出站方向）
//   - 追踪连接状态变更（ESTABLISHED → CLOSE）
//   - 聚合计数器按固定分类维度预聚合，避免维度爆炸
//
// 注意：
//   - 使用 tracepoint 而非 kprobe，兼容 CO-RE，无需内核头文件
//   - 不依赖 vmlinux.h，所有结构体手动定义
//   - 仅追踪聚合计数，不记录单条连接数据

#include <linux/bpf.h>
#include <linux/in.h>       // IPPROTO_TCP, IPPROTO_UDP
#include <bpf/bpf_helpers.h>

/* ============================================================
 * 分类常量定义
 * ============================================================ */

/* 方向分类 */
#define DIRECTION_IN    0
#define DIRECTION_OUT   1

/* 协议分类 */
#define PROTO_TCP       0
#define PROTO_UDP       1

/* 错误分类 */
#define ERR_TIMEOUT     0
#define ERR_REFUSED     1
#define ERR_RESET       2

/* TCP 状态常量（来自 linux/tcp.h） */
#define TCP_ESTABLISHED  1
#define TCP_SYN_SENT     2
#define TCP_SYN_RECV     3
#define TCP_FIN_WAIT1    4
#define TCP_FIN_WAIT2    5
#define TCP_TIME_WAIT    6
#define TCP_CLOSE        7
#define TCP_CLOSE_WAIT   8
#define TCP_LAST_ACK     9

/* 计算 map key: direction * 2 + protocol（最多 4 个条目） */
#define MAP_KEY(dir, proto) ((__u32)((dir) * 2 + (proto)))

/* ============================================================
 * BPF Map 定义（cilium/ebpf bpf2go 兼容格式）
 *
 * 全部使用 PERCPU_ARRAY：
 *   - 无需锁，每个 CPU 独立计数
 *   - 用户态读取时汇总各 CPU 数值
 *   - 适合高频更新、低频读取的计数器场景
 * ============================================================ */

/*
 * connect_total - 连接总数计数器
 * key = direction * 2 + protocol
 *   0: IN+TCP, 1: IN+UDP, 2: OUT+TCP, 3: OUT+UDP
 * value = 连接建立累计次数
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} connect_total SEC(".maps");

/*
 * connect_active - 当前活跃连接数
 * key = direction * 2 + protocol
 * value = 当前活跃连接数（建立时 +1，关闭时 -1）
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} connect_active SEC(".maps");

/*
 * connect_error_total - 连接错误计数器
 * key = 错误类型
 *   0: TIMEOUT   - 连接超时（SYN_SENT → CLOSE）
 *   1: REFUSED   - 连接被拒绝（RST in SYN_SENT/SYN_RECV）
 *   2: RESET     - 连接被重置（RST in ESTABLISHED/FIN_WAIT）
 * value = 错误累计次数
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} connect_error_total SEC(".maps");

/* ============================================================
 * tracepoint 上下文结构体定义
 * ============================================================ */

/*
 * tracepoint/sock/inet_sock_set_state 的参数结构
 *
 * 该 tracepoint 在内核 4.16+ 可用，在 TCP 状态变更时触发。
 * 字段布局参考内核源码：net/ipv4/inet_connection_sock.c
 *   trace_inet_sock_set_state(sk, oldstate, newstate)
 *
 * 布局（在 64 位系统上）：
 *   [0-7]   common fields (trace_entry: type+flags+preempt_count+pid)
 *   [8-15]  skbaddr  (const void *)
 *   [16-23] skaddr   (const void *)
 *   [24-27] oldstate (int)
 *   [28-31] newstate (int)
 *   [32-33] sport    (__u16)
 *   [34-35] dport    (__u16)
 *   [36-37] family   (__u16)
 *   [38-39] protocol (__u16)
 *   [40+]   saddr/daddr (省略，本程序不需要)
 */
struct trace_event_raw_inet_sock_set_state {
    __u64 pad;            /* 通用 tracepoint 头部（8 字节） */
    const void *skbaddr;  /* skb 地址 */
    const void *skaddr;   /* sock 地址 */
    int oldstate;         /* 变更前 TCP 状态 */
    int newstate;         /* 变更后 TCP 状态 */
    __u16 sport;          /* 源端口 */
    __u16 dport;          /* 目标端口 */
    __u16 family;         /* 地址族 (AF_INET=2, AF_INET6=10) */
    __u16 protocol;       /* 传输层协议 (IPPROTO_TCP=6, IPPROTO_UDP=17) */
    /* saddr/daddr 字段省略 — 不记录 IP 地址，避免维度爆炸 */
};

/* ============================================================
 * 辅助函数
 * ============================================================ */

/*
 * increment_counter - 递增 percpu_array 中指定 key 的计数器
 * percpu_array 的 bpf_map_lookup_elem 返回当前 CPU 的值指针，
 * 因此无需原子操作即可安全更新。
 */
static __always_inline void increment_counter(void *map, __u32 key)
{
    __u64 *val = bpf_map_lookup_elem(map, &key);
    if (val) {
        (*val)++;
    } else {
        /* percpu_array 不应走到此分支（key 始终 < max_entries），
         * 但保留作为防御性编程 */
        __u64 init = 1;
        bpf_map_update_elem(map, &key, &init, BPF_ANY);
    }
}

/*
 * decrement_counter - 递减 percpu_array 中指定 key 的计数器
 * 仅在值 > 0 时递减，防止下溢。
 */
static __always_inline void decrement_counter(void *map, __u32 key)
{
    __u64 *val = bpf_map_lookup_elem(map, &key);
    if (val && *val > 0) {
        (*val)--;
    }
}

/* ============================================================
 * TCP 状态变更追踪（核心 tracepoint）
 *
 * 追踪 TCP 连接的完整生命周期：
 *   出站: SYN_SENT → ESTABLISHED (成功) / CLOSE (失败)
 *   入站: SYN_RECV → ESTABLISHED (成功)
 *   关闭: ESTABLISHED → FIN_WAIT* / CLOSE_WAIT
 *   错误: 任何状态 → CLOSE (RST)
 * ============================================================ */
SEC("tracepoint/sock/inet_sock_set_state")
int trace_tcp_state_change(struct trace_event_raw_inet_sock_set_state *ctx)
{
    int oldstate = ctx->oldstate;
    int newstate = ctx->newstate;

    /* 仅关注 TCP 协议 */
    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    /* ----- 出站连接 (OUT) ----- */

    /* SYN_SENT → ESTABLISHED：出站 TCP 三次握手成功 */
    if (oldstate == TCP_SYN_SENT && newstate == TCP_ESTABLISHED) {
        __u32 key = MAP_KEY(DIRECTION_OUT, PROTO_TCP);
        increment_counter(&connect_total, key);
        increment_counter(&connect_active, key);
        return 0;
    }

    /* SYN_SENT → CLOSE：出站连接失败（超时或被拒绝） */
    if (oldstate == TCP_SYN_SENT && newstate == TCP_CLOSE) {
        increment_counter(&connect_error_total, ERR_TIMEOUT);
        return 0;
    }

    /* ----- 入站连接 (IN) ----- */

    /* SYN_RECV → ESTABLISHED：入站 TCP 三次握手成功 */
    if (oldstate == TCP_SYN_RECV && newstate == TCP_ESTABLISHED) {
        __u32 key = MAP_KEY(DIRECTION_IN, PROTO_TCP);
        increment_counter(&connect_total, key);
        increment_counter(&connect_active, key);
        return 0;
    }

    /* ----- 连接关闭（活跃数递减） ----- */

    /* ESTABLISHED → FIN_WAIT1：本端主动关闭（出站方向） */
    if (oldstate == TCP_ESTABLISHED && newstate == TCP_FIN_WAIT1) {
        __u32 key = MAP_KEY(DIRECTION_OUT, PROTO_TCP);
        decrement_counter(&connect_active, key);
        return 0;
    }

    /* ESTABLISHED → CLOSE_WAIT：对端主动关闭（入站方向） */
    if (oldstate == TCP_ESTABLISHED && newstate == TCP_CLOSE_WAIT) {
        __u32 key = MAP_KEY(DIRECTION_IN, PROTO_TCP);
        decrement_counter(&connect_active, key);
        return 0;
    }

    /* ----- 连接错误（RST 重置） ----- */

    /* 已建立连接收到 RST → CLOSE */
    if (newstate == TCP_CLOSE &&
        (oldstate == TCP_ESTABLISHED || oldstate == TCP_FIN_WAIT1 ||
         oldstate == TCP_FIN_WAIT2 || oldstate == TCP_CLOSE_WAIT)) {
        increment_counter(&connect_error_total, ERR_RESET);
        return 0;
    }

    /* SYN_RECV → CLOSE：入站连接被拒绝（RST 响应 SYN+ACK） */
    if (oldstate == TCP_SYN_RECV && newstate == TCP_CLOSE) {
        increment_counter(&connect_error_total, ERR_REFUSED);
        return 0;
    }

    return 0;
}

/* ============================================================
 * UDP 追踪
 *
 * UDP 是无连接协议，没有状态机。
 * 使用 kprobe 追踪 udp_sendmsg / udp_recvmsg 来统计收发次数。
 *
 * 注意：kprobe 需要内核符号表支持，兼容性不如 tracepoint，
 * 但 UDP 目前没有合适的 tracepoint 可用。
 * 此处作为预留功能，后续可根据需要启用。
 * ============================================================ */

/*
 * 追踪出站 UDP 发送
 * 每次 udp_sendmsg 调用即视为一次出站 UDP "连接"
 */
SEC("kprobe/udp_sendmsg")
int trace_udp_sendmsg(struct pt_regs *ctx)
{
    __u32 key = MAP_KEY(DIRECTION_OUT, PROTO_UDP);
    increment_counter(&connect_total, key);
    return 0;
}

/*
 * 追踪入站 UDP 接收
 * 每次 udp_recvmsg 调用即视为一次入站 UDP "连接"
 */
SEC("kprobe/udp_recvmsg")
int trace_udp_recvmsg(struct pt_regs *ctx)
{
    __u32 key = MAP_KEY(DIRECTION_IN, PROTO_UDP);
    increment_counter(&connect_total, key);
    return 0;
}

/* GPL 许可证声明 */
char LICENSE[] SEC("license") = "GPL";
