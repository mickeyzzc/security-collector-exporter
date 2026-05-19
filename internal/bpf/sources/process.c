// 进程执行追踪 BPF 程序
// 追踪 execve 系统调用和进程退出事件
// 使用 percpu_array map 进行内核态预聚合，避免维度爆炸
//
// 编译目标: cilium/ebpf bpf2go 兼容
// 内核要求: Linux 5.4+ (BTF 支持)

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* ============================================================
 * 常量与分类定义
 * ============================================================ */

// 进程分类 ID
#define PROC_SYSTEM      0    // 系统进程 (/usr/sbin, /usr/bin, /sbin, /bin)
#define PROC_USER        1    // 用户进程
#define PROC_CONTAINER   2    // 容器进程（通过 cgroup 检测）
#define PROC_SUSPICIOUS  3    // 可疑进程（shell/python/perl 等 + 非系统路径）
#define PROC_MAX_CATEGORY 4

// 路径前缀长度限制（BPF verifier 对循环次数有上限）
#define PATH_PREFIX_LEN  16

/* ============================================================
 * BPF Map 定义
 * ============================================================ */

// 采样率配置 map（用户态写入）
// key=0, value: 1=始终采集, N=每 N 次采集 1 次
// 当前版本：内核端始终计数，采样由用户态控制读取频率
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} config_map SEC(".maps");

// 进程执行分类计数 map（按分类聚合 execve 次数）
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, PROC_MAX_CATEGORY);
    __type(key, __u32);
    __type(value, __u64);
} exec_category_count SEC(".maps");

// 进程退出分类计数 map（按分类聚合退出次数）
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, PROC_MAX_CATEGORY);
    __type(key, __u32);
    __type(value, __u64);
} exit_category_count SEC(".maps");

// 活跃进程计数 map（当前各类活跃进程数）
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, PROC_MAX_CATEGORY);
    __type(key, __u32);
    __type(value, __u64);
} active_process_count SEC(".maps");

// PID→分类 hash map（用于 exit 时查找原始 execve 分类）
// key: pid_tgid (bpf_get_current_pid_tgid()), value: category
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);    /* pid_tgid */
    __type(value, __u32);  /* category */
} pid_category SEC(".maps");

/* ============================================================
 * 辅助函数
 * ============================================================ */

// 递增指定 map 中某个分类的计数器
static __always_inline void increment_category(void *map, __u32 category)
{
    __u64 *count = bpf_map_lookup_elem(map, &category);
    if (count) {
        (*count)++;
    }
}

// 递减指定 map 中某个分类的计数器
static __always_inline void decrement_category(void *map, __u32 category)
{
    __u64 *count = bpf_map_lookup_elem(map, &category);
    if (count && *count > 0) {
        (*count)--;
    }
}

// 从 bpf_get_current_cgroup_id() 获取 cgroup ID（用于容器检测）
// 返回 0 表示非容器环境
static __always_inline __u64 get_cgroup_id(void)
{
    return bpf_get_current_cgroup_id();
}

// 检查路径是否为系统路径前缀
// 返回: 1=系统路径, 0=非系统路径
static __always_inline int is_system_path(const char *path)
{
    // 逐字节比较，BPF verifier 要求有限循环
    // /usr/sbin, /usr/bin, /sbin, /bin
    char prefix[PATH_PREFIX_LEN] = {};
    int ret;

    // 读取路径前缀到本地缓冲区（BPF verifier 要求栈上访问）
    ret = bpf_probe_read_user_str(prefix, sizeof(prefix), path);
    if (ret < 0)
        return 0;

    // 检查 /bin/ (4字节)
    if (prefix[0] == '/' && prefix[1] == 'b' &&
        prefix[2] == 'i' && prefix[3] == 'n' && prefix[4] == '/')
        return 1;

    // 检查 /sbin/ (5字节)
    if (prefix[0] == '/' && prefix[1] == 's' &&
        prefix[2] == 'b' && prefix[3] == 'i' &&
        prefix[4] == 'n' && prefix[5] == '/')
        return 1;

    // 检查 /usr/ (4字节前缀)
    if (prefix[0] == '/' && prefix[1] == 'u' &&
        prefix[2] == 's' && prefix[3] == 'r' && prefix[4] == '/')
        return 1;

    return 0;
}

// 检查文件名是否为可疑解释器（shell/python/perl 等）
static __always_inline int is_suspicious_interpreter(const char *path)
{
    char buf[16] = {};
    int ret;

    // 提取文件名的最后部分（跳过路径）
    // BPF 中无法高效做 strrchr，简化处理：读取最后几个字节
    ret = bpf_probe_read_user_str(buf, sizeof(buf), path);
    if (ret < 0)
        return 0;

    // 检查常见可疑解释器名称出现在路径中
    // 这里只做简单的前缀匹配（路径开头）
    // bash, sh, python, perl, ruby, php, node
    // 实际上应该检查路径末尾，但 BPF 循环受限

    // 检查 /sh (覆盖 bash, sh, dash 等)
    // 简化：不在此处做复杂字符串匹配，由分类逻辑决定
    return 0;
}

// 根据进程 comm 名猜测分类（用于 BPF 加载前已存在的进程）
// 仅匹配前 4 字节，BPF verifier 友好
static __always_inline __u32 classify_by_comm(void)
{
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    /* 匹配已知系统服务前缀 */
    if (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's' && comm[3] == 't') return PROC_SYSTEM; /* systemd/systemd-udevd */
    if (comm[0] == 's' && comm[1] == 's' && comm[2] == 'h' && comm[3] == 'd') return PROC_SYSTEM; /* sshd */
    if (comm[0] == 'c' && comm[1] == 'r' && comm[2] == 'o' && comm[3] == 'n') return PROC_SYSTEM; /* cron/crond */
    if (comm[0] == 'd' && comm[1] == 'b' && comm[2] == 'u' && comm[3] == 's') return PROC_SYSTEM; /* dbus-daemon */
    if (comm[0] == 'n' && comm[1] == 'g' && comm[2] == 'i' && comm[3] == 'n') return PROC_SYSTEM; /* nginx */
    if (comm[0] == 'a' && comm[1] == 'p' && comm[2] == 'a' && comm[3] == 'c') return PROC_SYSTEM; /* apache2 */
    if (comm[0] == 'h' && comm[1] == 't' && comm[2] == 't' && comm[3] == 'p') return PROC_SYSTEM; /* httpd */
    if (comm[0] == 'k' && comm[1] == 'w' && comm[2] == 'o' && comm[3] == 'r') return PROC_SYSTEM; /* kworker kernel threads */

    return PROC_USER;
}

// 分类进程路径
// 返回分类 ID (PROC_SYSTEM / PROC_USER / PROC_CONTAINER / PROC_SUSPICIOUS)
static __always_inline int classify_process(const char *filename)
{
    // 1. 检查系统路径前缀
    if (is_system_path(filename))
        return PROC_SYSTEM;

    // 2. 检查容器进程（通过 cgroup）
    if (get_cgroup_id() != 0)
        return PROC_CONTAINER;

    // 3. 默认分类为用户进程
    // TODO: 后续可增加可疑进程检测（解释器 + 非系统路径）
    return PROC_USER;
}

/* tracepoint 上下文结构体（手动定义，不依赖内核头文件） */
struct trace_event_raw_sys_enter {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;
    int   __syscall_nr;
    __u64 args[6];
};

struct trace_event_raw_sched_process_template {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;
    char  comm[16];
    __s32 pid;
    __s32 tgid;
    int   __pid;
    int   __tgid;
};

/* ============================================================
 * Tracepoint 处理函数
 * ============================================================ */

// 追踪进程执行（execve 系统调用入口）
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    // 从系统调用参数获取文件名指针
    // sys_enter_execve 的 args[0] 即为 filename 参数
    const char *filename = (const char *)ctx->args[0];
    if (!filename)
        return 0;

    // 分类并递增计数器
    __u32 category = classify_process(filename);
    increment_category(&exec_category_count, category);
    increment_category(&active_process_count, category);

    // 存储 PID→分类映射，供 exit 时查找
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pid_category, &pid_tgid, &category, BPF_ANY);

    return 0;
}

// 追踪进程退出（sched_process_exit 追踪点）
SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid & 0xFFFFFFFF);
    __u32 tgid = (__u32)(pid_tgid >> 32);

    // 只统计线程组主进程退出，忽略子线程退出
    if (pid != tgid)
        return 0;

    // 从 hash map 查找 execve 时记录的分类
    __u32 category = PROC_USER;
    __u32 *cat_ptr = bpf_map_lookup_elem(&pid_category, &pid_tgid);
    if (cat_ptr) {
        category = *cat_ptr;
        bpf_map_delete_elem(&pid_category, &pid_tgid);
    } else {
        // BPF 加载前已存在的进程，用 comm 猜测分类
        category = classify_by_comm();
    }

    increment_category(&exit_category_count, category);
    decrement_category(&active_process_count, category);

    return 0;
}

/* ============================================================
 * 许可证声明
 * ============================================================ */

char LICENSE[] SEC("license") = "GPL";
