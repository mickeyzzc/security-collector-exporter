// 进程执行追踪 BPF 程序
// 追踪 execve 系统调用和进程退出事件
// 使用 percpu_array map 进行内核态预聚合，避免维度爆炸
//
// 编译目标: cilium/ebpf bpf2go 兼容
// 内核要求: Linux 5.4+ (BTF 支持)

#include <linux/types.h>
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

// 从 bpf_get_current_task() 获取 cgroup ID（用于容器检测）
// 返回 0 表示获取失败或非容器环境
static __always_inline __u64 get_cgroup_id(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    // 使用 BPF CO-RE 读取 cgroup 信息
    // 在容器中，cgroup 通常包含 "docker"、"kubepods" 等标识
    // 简化实现：返回 cgroup 的 inode 号（非零表示在 cgroup 中）
    return 0; // 占位，后续通过 bpf_get_current_cgroup_id() 获取
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

// 分类进程路径
// 返回分类 ID (PROC_SYSTEM / PROC_USER / PROC_CONTAINER / PROC_SUSPICIOUS)
static __always_inline int classify_process(const char *filename)
{
    // 1. 检查系统路径前缀
    if (is_system_path(filename))
        return PROC_SYSTEM;

    // 2. 检查容器进程（通过 cgroup）
    // 后续任务会实现完整的 cgroup 检测
    // if (get_cgroup_id() != 0)
    //     return PROC_CONTAINER;

    // 3. 默认分类为用户进程
    // TODO: 后续可增加可疑进程检测（解释器 + 非系统路径）
    return PROC_USER;
}

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

    return 0;
}

// 追踪进程退出（sched_process_exit 追踪点）
SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    // 进程退出时无法准确获取原始 execve 路径
    // 使用当前 task comm 做简单分类
    // 简化实现：统一使用 USER 分类
    // TODO: 后续可通过 task->comm 或关联 map 改进分类精度
    __u32 category = PROC_USER;

    increment_category(&exit_category_count, category);
    decrement_category(&active_process_count, category);

    return 0;
}

/* ============================================================
 * 许可证声明
 * ============================================================ */

char LICENSE[] SEC("license") = "GPL";
