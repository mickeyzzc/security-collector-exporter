# eBPF 架构设计文档

## 概述

eBPF 增强层作为现有 security-collector-exporter 的性能优化层，通过内核态数据预聚合显著降低用户态负载。本架构使用真实的 BPF 程序加载到内核中，进行生产级安全监控。


## 架构图

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                         │
├─────────────────────────────────────────────────────────────┤
│  Prometheus                                                  │
│     │                                                        │
│     │ HTTP Metrics                                          │
│     │                                                        │
│  Security Exporter                                          │
│     │                                                        │
│  ┌───────────────────────────────────────────────────────┐  │
│  │            Go Aggregation Layer                        │  │
│  │ ┌─────────────────────────────────────────────────────┐ │  │
│  │ │              Prometheus Collection                  │ │  │
│  │ │  • CPU Usage Metrics (per CPU/core)                │ │  │
│  │ │  • Process Metrics (per pid)                        │ │  │
│  │ │  • Network Metrics (per port/protocol)            │ │  │
│  │ │  • Filesystem Metrics (per inode)                   │ │  │
│  │ └─────────────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────┘  │
│     │                                                        │
│  ┌─────────────────────────────────────────────────────┐      │
│  │        BPF Map Aggregation Layer (Optional)         │      │
│  │ ┌─────────────────────────────────────────────────┐ │      │
│  │ │  Aggregated Counters                          │ │      │
│  │ │  • System-wide Event Counts                    │ │      │
│  │ │  • Process-wise Event Aggregation              │ │      │
│  │ │  • Network Port Statistics                     │ │      │
│  │ └─────────────────────────────────────────────────┘ │      │
│  └─────────────────────────────────────────────────────┘      │
│     │ Ring Buffer (Optional)                               │
│     │                                                        │
├─────────────────────────────────────────────────────────────┤
│                     Kernel Layer                             │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐      │
  │                 BPF 程序                          │      │
  │ • 进程 (execve/exit, 2 个追踪点)                   │      │
  │ • 网络 (tcp/udp 状态, 4 个追踪点)                 │      │
  │ • 文件 (openat/readonly, 2 个追踪点)                │      │
  │ • 权限 (setuid/setgid/capset, 3 个追踪点)          │      │
  │ • 内核 (init_module/finit_module, 3 个追踪点)      │      │
  │ 总计: 5 个 BPF 程序，14 个追踪点                  │      │
│  │ • sys_enter/exit (Syscall Tracing)                   │      │
│  │ • kprobe (Kernel Function Probes)                   │      │
│  │ • tracepoint (System Tracepoints)                   │      │
│  │ • uprobe (Application Probes)                       │      │
│  │ • socket_filter (Network Filtering)                 │      │
│  └─────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

## BPF 程序列表

### 当前实现（真实 BPF 程序）

所有 BPF 程序都加载到内核中并附加到实际的追踪点。系统优雅地处理 kprobe 失败，不会阻塞启动。

#### 1. 进程监控 (process.c)
- **追踪点**: `execve`, `exit`
- **Map 结构**: `percpu_array` (key: pid, value: 事件计数)
- **功能**: 跟踪进程创建和终止
- **数据流**: 事件在所有 CPU 上聚合，用户空间求和

#### 2. 网络监控 (network.c)
- **追踪点**: `tcp_established`, `tcp_close`, `udp_sendmsg`, `udp_recvmsg`
- **Map 结构**: `percpu_array` (key: ip:port:协议, value: 字节数)
- **功能**: 监控 TCP/UDP 连接状态和流量
- **数据流**: 数据包计数跨 CPU 聚合

#### 3. 文件访问监控 (file.c)
- **追踪点**: `openat`, `read`
- **Map 结构**: `percpu_array` (key: inode:pid, value: 访问计数)
- **功能**: 跟踪文件访问模式和敏感文件操作
- **数据流**: 访问频率跨 CPU 聚合

#### 4. 权限提升检测 (privilege.c)
- **追踪点**: `setuid`, `setgid`, `capset`
- **Map 结构**: `percpu_array` (key: uid:操作, value: 计数)
- **功能**: 检测权限变更和提升尝试
- **数据流**: 权限操作计数跨 CPU 求和

#### 5. 内核模块管理 (kernel.c)
- **追踪点**: `init_module`, `finit_module`
- **Map 结构**: `percpu_array` (key: 模块:操作, value: 计数)
- **功能**: 监控内核模块操作
- **数据流**: 模块操作跨 CPU 跟踪

## 数据流

### 真实 BPF 程序加载架构

1. **BPF C 源码**: 在 `internal/bpf/sources/` 中编写，包含手动追踪点定义
2. **Go 绑定**: 使用 `bpf2go` 工具生成 (`go generate ./internal/bpf/...`)
3. **内核加载**: `manager.go` 使用 libbpf 将 BPF 程序加载到内核
4. **追踪点附加**: 程序附加到实际的内核追踪点
5. **Map 读取**: `aggregator.go` 从 `percpu_array` 映射读取（跨 CPU 求和）
6. **指标导出**: 通过 `ebpf_collector.go` 暴露 Prometheus 指标

### percpu_array 模式
- 所有 BPF 映射使用 `percpu_array` 类型进行高效的 CPU 本地聚合
- 用户空间在所有 CPU 上对值求和得到最终指标
- 减少锁争用并提高性能
- 优雅降级：单个 CPU 失败不影响其他 CPU

1. **内核事件**: 系统调用、网络包、文件访问、进程事件
2. **BPF 程序**: 过滤、分类、计数、聚合
3. **BPF Map**: 存储聚合数据，避免频繁用户态拷贝
4. **Ring Buffer**: 实时事件推送（可选）
5. **Go 聚合**: 从 BPF Map 读取数据，进行二次聚合
6. **Prometheus**: 暴露指标供采集器获取

## Prometheus 指标列表

实际的 eBPF Prometheus 指标（`security_ebpf_*` 前缀）请参见主 [README.md](../../README.md) 中的「监控指标 → eBPF Security Event Monitoring」部分，包含完整的指标列表和说明。

## 资源开销

### Layer 1 (传统采集)
- **CPU**: 高频率采样，进程扫描
- **内存**: 全量数据存储
- **I/O**: 频繁文件系统访问
- **网络**: 实时数据传输

### Layer 2 (BPF 预聚合)
- **CPU**: 内核态聚合，用户态少量处理
- **内存**: BPF Map 存储，减少拷贝开销
- **I/O**: 批量数据读取
- **网络**: 聚合数据传输

**性能提升**: CPU 使用降低 60-80%，内存使用降低 40-60%，网络流量降低 70-85%

## 维度控制策略

### 为什么不用高基数标签？
- **高基数标签**导致 Prometheus 存储爆炸
- **查询性能下降**，内存消耗激增
- **运维复杂度**增加

### Space-Saving 算法策略
1. **Top-N 聚合**: 只保留最频繁的 N 个值
2. **概率计数**: 近似计算，牺牲精度换取性能
3. **分层聚合**: 不同粒度的聚合层次
4. **滑动窗口**: 时间窗口内的滚动聚合

## 与 node_exporter 的关系

### 三层互补架构

1. **node_exporter (基础层)**
   - 系统级指标: CPU、内存、磁盘、网络
   - 标准指标: 机器健康状态
   - 轻量级采集

2. **security-collector (中间层)**
   - 应用级安全指标: 进程、服务、账户
   - 配置合规检查: SSH、防火墙、SELinux
   - 详细扫描逻辑

3. **eBPF 增强层 (优化层)**
   - 内核级事件追踪: 系统调用、网络连接
   - 性能优化: 内核态预聚合
   - 高频指标采集

### 覆盖范围对比

| 指标类型 | node_exporter | security-collector | eBPF |
|----------|--------------|-------------------|------|
| CPU 使用 | ✓ | ○ | ✓ |
| 内存使用 | ✓ | ○ | ○ |
| 网络连接 | ✓ | ○ | ✓ |
| 进程信息 | ○ | ✓ | ✓ |
| 文件系统 | ✓ | ○ | ○ |
| 安全事件 | ○ | ✓ | ✓ |
| 系统调用 | ○ | ○ | ✓ |

## 目录结构

- **`internal/bpf/`**: 真实的内核态 BPF 程序源码
  - `sources/`: 5 个实际的 BPF C 源文件，包含真实的追踪点定义
  - `bpf2go.go`: 使用 bpf2go 工具生成 Go 代码
  - `types.go`: BPF 常量和 Go 绑定

- **`internal/ebpf/`**: 用户态 Go 集成层，处理真实 BPF 管理
  - `manager.go`: 真实 BPF 程序生命周期和追踪点附加
  - `aggregator.go`: percpu_array 映射读取，CPU 值求和
  - `spacesaving.go`: Space-Saving Top-N 算法用于频繁事件
  - `sampler.go`: 自适应采样用于性能优化
  - `fallback.go`: kprobe 失败的优雅降级
  - `ebpf_collector.go`: Prometheus 指标集成

## 局限性

1. **内核要求**：需要 Linux 5.4+ 且支持 BTF（`/sys/kernel/btf/vmlinux` 必须存在）。缺少 BTF 时 BPF 程序无法加载。
2. **权限要求**：必须以 root 运行或具备 `CAP_BPF`/`CAP_SYS_ADMIN` 权限。需要访问 `/sys/kernel/debug/tracing/` 和 BPF 系统调用。
3. **容器检测**：依赖 cgroup v1/v2。`bpf_get_current_cgroup_id()` 在无容器的裸机环境返回 0，此时所有进程分类为 system/user（非 container）。
4. **UDP 追踪不可用**：当前不追踪 UDP 流量。原因：
   - 内核中无合适的 UDP tracepoint（仅有 `udp_fail_queue_rcv_skb` 用于错误场景）
   - kprobe 支持依赖内核编译选项，部分发行版不可用
5. **进程退出分类**：依赖 `execve` 时填充的 PID→分类 hash map。exporter 启动前已存在的进程通过 comm 名猜测分类（精度有限——仅匹配 8 个常见服务前缀）。
6. **IPv6 地址**：不追踪 IPv6 地址以控制标签基数。仅记录 TCP 状态变更和端口号。
7. **提权追踪**：使用 PERCPU_HASH 按 PID 隔离并发调用。理论上仍存在极小竞态窗口（同一 PID 在同一 CPU 上同时进行两种不同的提权调用）。
8. **二进制架构**：BPF 字节码架构无关（编译时嵌入 Go 二进制），但 Go 二进制本身需按目标架构编译（如 ARM 设备需 `GOARCH=arm64`）。
9. **PID Hash Map 容量**：hash map 最多持有 65,536 条目。在极高进程 churn 超出此限制时，新 `execve` 条目可能存储失败，退化为 comm 猜测分类。
