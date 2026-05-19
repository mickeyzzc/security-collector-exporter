// 提权行为追踪 BPF 程序
// 追踪 setuid、setgid、capset 系统调用，统计提权尝试次数及成功/失败分布
// 使用 percpu_array map 按类型和结果分类计数

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* tracepoint 上下文结构体（手动定义，不依赖内核头文件） */
struct trace_event_raw_sys_enter {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;
    int   __syscall_nr;
    __u64 args[6];
};

struct trace_event_raw_sys_exit {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;
    int   __syscall_nr;
    __s64 ret;
};

// 提权调用类型
#define TYPE_SETUID  0
#define TYPE_SETGID  1
#define TYPE_CAPSET  2

// 调用结果
#define RESULT_SUCCESS 0
#define RESULT_FAILURE 1

// 根据类型和结果计算 map 索引: type * 2 + result
#define MAP_KEY(type, result) ((type) * 2 + (result))

// percpu_array map: 按 (类型, 结果) 统计提权调用次数
// 索引布局: [0]=SETUID_SUCCESS, [1]=SETUID_FAILURE,
//           [2]=SETGID_SUCCESS, [3]=SETGID_FAILURE,
//           [4]=CAPSET_SUCCESS, [5]=CAPSET_FAILURE
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, __u64);
} privilege_escalation_total SEC(".maps");

// 用于在 sys_enter 和 sys_exit 之间传递调用类型的 percpu hash
// 按 pid 隔离，避免同 CPU 上不同进程的竞态
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);    /* pid */
    __type(value, __u32);  /* call type */
} call_type_tmp SEC(".maps");

// ========== 通用辅助函数 ==========

// 记录一次提权调用结果
static __always_inline void record_privilege_call(__u32 type, __u32 result)
{
    __u32 key = MAP_KEY(type, result);
    __u64 *val = bpf_map_lookup_elem(&privilege_escalation_total, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&privilege_escalation_total, &key, &init, BPF_NOEXIST);
    }
}

// 保存当前调用的类型到 percpu 临时 map
static __always_inline void save_call_type(__u32 type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid & 0xFFFFFFFF);
    bpf_map_update_elem(&call_type_tmp, &pid, &type, BPF_ANY);
}

// 从 percpu 临时 map 读取调用类型
static __always_inline __u32 load_call_type(void)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid & 0xFFFFFFFF);
    __u32 *val = bpf_map_lookup_elem(&call_type_tmp, &pid);
    if (val) {
        __u32 t = *val;
        bpf_map_delete_elem(&call_type_tmp, &pid);
        return t;
    }
    return 0;
}

// ========== setuid 追踪 ==========

// setuid 入口: 记录调用类型
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid_enter(struct trace_event_raw_sys_enter *ctx)
{
    save_call_type(TYPE_SETUID);
    return 0;
}

// setuid 出口: 根据返回值判断成功/失败
// 返回值: 0 = 成功, -1 = 失败
SEC("tracepoint/syscalls/sys_exit_setuid")
int trace_setuid_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 type = load_call_type();
    __u32 result = (ctx->ret == 0) ? RESULT_SUCCESS : RESULT_FAILURE;
    record_privilege_call(type, result);
    return 0;
}

// ========== setgid 追踪 ==========

// setgid 入口: 记录调用类型
SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid_enter(struct trace_event_raw_sys_enter *ctx)
{
    save_call_type(TYPE_SETGID);
    return 0;
}

// setgid 出口: 根据返回值判断成功/失败
SEC("tracepoint/syscalls/sys_exit_setgid")
int trace_setgid_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 type = load_call_type();
    __u32 result = (ctx->ret == 0) ? RESULT_SUCCESS : RESULT_FAILURE;
    record_privilege_call(type, result);
    return 0;
}

// ========== capset 追踪 ==========

// capset 入口: 记录调用类型
SEC("tracepoint/syscalls/sys_enter_capset")
int trace_capset_enter(struct trace_event_raw_sys_enter *ctx)
{
    save_call_type(TYPE_CAPSET);
    return 0;
}

// capset 出口: 根据返回值判断成功/失败
SEC("tracepoint/syscalls/sys_exit_capset")
int trace_capset_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 type = load_call_type();
    __u32 result = (ctx->ret == 0) ? RESULT_SUCCESS : RESULT_FAILURE;
    record_privilege_call(type, result);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
