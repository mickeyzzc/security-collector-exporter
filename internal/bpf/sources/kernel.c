// 内核模块加载追踪 BPF 程序
// 追踪 init_module 和 finit_module 系统调用
// 使用 percpu_array map 进行内核态预聚合，对检测 rootkit 行为非常有价值
//
// 编译目标: cilium/ebpf bpf2go 兼容
// 内核要求: Linux 5.4+ (BTF 支持)

#include <linux/types.h>
#include <bpf/bpf_helpers.h>

/* ============================================================
 * 常量与分类定义
 * ============================================================ */

// 模块加载动作分类
#define ACTION_LOAD      0    // init_module 系统调用（从内存缓冲区加载模块）
#define ACTION_LOAD_FILE 1    // finit_module 系统调用（从文件描述符加载模块）
#define ACTION_MAX       2

/* ============================================================
 * BPF Map 定义
 * ============================================================ */

// 模块加载计数 map（按动作类型聚合）
// key: 动作类型 (ACTION_LOAD / ACTION_LOAD_FILE)
// value: 累计加载次数
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, ACTION_MAX);
    __type(key, __u32);
    __type(value, __u64);
} module_load_total SEC(".maps");

/* ============================================================
 * 辅助函数
 * ============================================================ */

// 递增指定动作类型的计数器
static __always_inline void increment_action(__u32 action)
{
    __u64 *count = bpf_map_lookup_elem(&module_load_total, &action);
    if (count) {
        (*count)++;
    }
}

/* ============================================================
 * Tracepoint 处理程序
 * ============================================================ */

// 追踪 init_module 系统调用（从内存缓冲区加载内核模块）
// 典型场景: insmod 使用此系统调用
SEC("tracepoint/syscalls/sys_enter_init_module")
int trace_init_module(struct trace_event_raw_sys_enter *ctx)
{
    increment_action(ACTION_LOAD);
    return 0;
}

// 追踪 finit_module 系统调用（从文件描述符加载内核模块）
// 典型场景: modprobe / insmod 从 .ko 文件加载
SEC("tracepoint/syscalls/sys_enter_finit_module")
int trace_finit_module(struct trace_event_raw_sys_enter *ctx)
{
    increment_action(ACTION_LOAD_FILE);
    return 0;
}

// BPF 程序许可证（必须与内核兼容）
char LICENSE[] SEC("license") = "GPL";
