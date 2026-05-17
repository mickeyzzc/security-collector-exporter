// file.c — BPF 程序：监控敏感文件访问
// 通过追踪 openat 系统调用，对敏感文件访问进行分类计数聚合。
// 使用 percpu_array map 实现无锁高频计数。

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

/* ============================================================
 * 常量定义
 * ============================================================ */

/* 严重等级 */
#define SEVERITY_CRITICAL  0  /* 关键文件：密码/影子文件 */
#define SEVERITY_WARNING   1  /* 警告文件：SSH/认证配置 */
#define SEVERITY_INFO      2  /* 一般文件：系统配置 */

/* 操作类型 */
#define OP_READ   0           /* 读操作 */
#define OP_WRITE  1           /* 写操作 */

/* openat flags 用于判断读写 */
#define O_WRONLY  1
#define O_RDWR    2

/* 文件路径最大长度 */
#define PATH_MAX_LEN 256

/* map 最大条目数：3 个严重等级 × 2 种操作 = 6 */
#define MAP_MAX_ENTRIES 6

/* ============================================================
 * BPF Map 定义
 * ============================================================ */

/*
 * file_access_total — 敏感文件访问计数器
 *
 * key 计算方式：severity * 2 + operation
 *   - severity: 0=critical, 1=warning, 2=info
 *   - operation: 0=read, 1=write
 *
 * 示例：
 *   key=0 → critical+read    (/etc/shadow 被读取)
 *   key=1 → critical+write   (/etc/shadow 被写入)
 *   key=2 → warning+read     (/etc/ssh/sshd_config 被读取)
 *   key=3 → warning+write    (/etc/ssh/sshd_config 被写入)
 *   key=4 → info+read        (/etc/hosts 被读取)
 *   key=5 → info+write       (/etc/hosts 被写入)
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAP_MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} file_access_total SEC(".maps");

/* ============================================================
 * 辅助函数：字符串前缀匹配（逐字符比较）
 *
 * BPF verifier 不允许使用标准库 strcmp，
 * 必须逐字符手动比较。最多比较 len 个字符。
 * ============================================================ */

static __always_inline int prefix_match(const char *str, const char *prefix, int len)
{
    /* BPF verifier 要求循环有界 */
    for (int i = 0; i < len; i++) {
        if (prefix[i] == '\0')
            return 1;  /* 前缀匹配成功 */
        if (str[i] != prefix[i])
            return 0;  /* 不匹配 */
    }
    return 1;  /* 长度范围内全部匹配 */
}

/* ============================================================
 * 辅助函数：从路径判断敏感等级
 *
 * 返回值：
 *   0 = SEVERITY_CRITICAL (/etc/shadow, /etc/passwd, /etc/gshadow)
 *   1 = SEVERITY_WARNING  (/etc/ssh/sshd_config, /etc/sudoers, /etc/pam.d/*)
 *   2 = SEVERITY_INFO     (/etc/hosts, /etc/resolv.conf, /etc/fstab)
 *  -1 = 非敏感文件
 * ============================================================ */

static __always_inline int get_severity(const char *path)
{
    /* ---- CRITICAL 级别：密码/影子文件 ---- */

    /* /etc/shadow */
    if (prefix_match(path, "/etc/shadow", sizeof("/etc/shadow") - 1))
        return SEVERITY_CRITICAL;

    /* /etc/shadow- (备份) */
    if (prefix_match(path, "/etc/shadow-", sizeof("/etc/shadow-") - 1))
        return SEVERITY_CRITICAL;

    /* /etc/passwd */
    if (prefix_match(path, "/etc/passwd", sizeof("/etc/passwd") - 1))
        return SEVERITY_CRITICAL;

    /* /etc/passwd- (备份) */
    if (prefix_match(path, "/etc/passwd-", sizeof("/etc/passwd-") - 1))
        return SEVERITY_CRITICAL;

    /* /etc/gshadow */
    if (prefix_match(path, "/etc/gshadow", sizeof("/etc/gshadow") - 1))
        return SEVERITY_CRITICAL;

    /* ---- WARNING 级别：认证/SSH 配置 ---- */

    /* /etc/ssh/sshd_config */
    if (prefix_match(path, "/etc/ssh/sshd_config", sizeof("/etc/ssh/sshd_config") - 1))
        return SEVERITY_WARNING;

    /* /etc/ssh/sshd_config.d/ */
    if (prefix_match(path, "/etc/ssh/sshd_config.d/", sizeof("/etc/ssh/sshd_config.d/") - 1))
        return SEVERITY_WARNING;

    /* /etc/sudoers */
    if (prefix_match(path, "/etc/sudoers", sizeof("/etc/sudoers") - 1))
        return SEVERITY_WARNING;

    /* /etc/sudoers.d/ */
    if (prefix_match(path, "/etc/sudoers.d/", sizeof("/etc/sudoers.d/") - 1))
        return SEVERITY_WARNING;

    /* /etc/pam.d/ */
    if (prefix_match(path, "/etc/pam.d/", sizeof("/etc/pam.d/") - 1))
        return SEVERITY_WARNING;

    /* ---- INFO 级别：系统配置 ---- */

    /* /etc/hosts */
    if (prefix_match(path, "/etc/hosts", sizeof("/etc/hosts") - 1))
        return SEVERITY_INFO;

    /* /etc/resolv.conf */
    if (prefix_match(path, "/etc/resolv.conf", sizeof("/etc/resolv.conf") - 1))
        return SEVERITY_INFO;

    /* /etc/fstab */
    if (prefix_match(path, "/etc/fstab", sizeof("/etc/fstab") - 1))
        return SEVERITY_INFO;

    /* 非敏感文件 */
    return -1;
}

/* ============================================================
 * BPF 程序：追踪 openat 系统调用
 *
 * tracepoint: syscalls:sys_enter_openat
 *
 * 参数：
 *   args->dfd  = 目录文件描述符（AT_FDCWD = -100 表示当前目录）
 *   args->filename = 文件路径指针（用户空间）
 *   args->flags  = 打开标志（O_WRONLY, O_RDWR 等）
 * ============================================================ */

struct openat_args {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;

    int   __syscall_nr;
    int   dfd;
    const char *filename;
    int   flags;
    __u16 mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct openat_args *ctx)
{
    char path[PATH_MAX_LEN] = {};

    /* 从用户空间读取文件路径 */
    int ret = bpf_probe_read_user_str(path, sizeof(path), ctx->filename);
    if (ret <= 0)
        return 0;  /* 读取失败，忽略 */

    /* 判断敏感等级 */
    int severity = get_severity(path);
    if (severity < 0)
        return 0;  /* 非敏感文件，忽略 */

    /* 判断读/写操作 */
    __u32 op = OP_READ;  /* 默认读操作 */
    if ((ctx->flags & O_WRONLY) || (ctx->flags & O_RDWR))
        op = OP_WRITE;

    /* 计算 map key: severity * 2 + operation */
    __u32 key = (__u32)(severity) * 2 + op;

    /* 更新计数器 */
    __u64 *count = bpf_map_lookup_elem(&file_access_total, &key);
    if (count)
        (*count)++;
    else {
        __u64 init_val = 1;
        bpf_map_update_elem(&file_access_total, &key, &init_val, BPF_ANY);
    }

    return 0;
}

/* GPL 许可声明，部分 BPF 辅助函数要求 */
char LICENSE[] SEC("license") = "GPL";
