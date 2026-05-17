# eBPF 架构设计文档

## 概述

eBPF 增强层作为现有 security-collector-exporter 的性能优化层，通过内核态数据预聚合显著降低用户态负载。本架构设计聚焦于最小化侵入性、保持兼容性，同时提供约 55 条高精度安全指标。

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
│  │                 BPF Programs                          │      │
│  │ • sys_enter/exit (Syscall Tracing)                   │      │
│  │ • kprobe (Kernel Function Probes)                   │      │
│  │ • tracepoint (System Tracepoints)                   │      │
│  │ • uprobe (Application Probes)                       │      │
│  │ • socket_filter (Network Filtering)                 │      │
│  └─────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

## BPF 程序列表

### 1. 系统调用追踪 (sys_enter/sys_exit)
- **追踪点**: `sys_enter_*`, `sys_exit_*`
- **Map 结构**: `syscall_stats` (key: syscall_id + pid, value: count + duration)
- **分类逻辑**: 系统调用类型、进程ID、调用频率、耗时统计

### 2. 进程生命周期追踪 (sched_process_* )
- **追踪点**: `sched_process_exec`, `sched_process_exit`
- **Map 结构**: `process_events` (key: pid + timestamp, value: event_type)
- **分类逻辑**: 进程创建、退出、执行路径、资源使用

### 3. 网络连接追踪 (tcp/udp/v4/v6)
- **追踪点**: `tcp_*`, `udp_*`, `inet_*`
- **Map 结构**: `network_stats` (key: ip_port + protocol, value: packet_count + byte_count)
- **分类逻辑**: 连接状态、端口分布、协议类型、流量统计

### 4. 文件系统访问追踪 (vfs_* )
- **追踪点**: `vfs_read`, `vfs_write`, `vfs_open`
- **Map 结构**: `file_access` (key: inode + process, value: access_count + byte_count)
- **分类逻辑**: 文件访问模式、进程访问频率、读写比例

### 5. 安全事件追踪 (security_* )
- **追踪点**: `security_*`, `avc_*`
- **Map 结构**: `security_events` (key: event_type + uid, value: count + severity)
- **分类逻辑**: SELinux事件、权限变更、认证失败、异常访问

## 数据流

1. **内核事件**: 系统调用、网络包、文件访问、进程事件
2. **BPF 程序**: 过滤、分类、计数、聚合
3. **BPF Map**: 存储聚合数据，避免频繁用户态拷贝
4. **Ring Buffer**: 实时事件推送（可选）
5. **Go 聚合**: 从 BPF Map 读取数据，进行二次聚合
6. **Prometheus**: 暴露指标供采集器获取

## Prometheus 指标列表

### CPU 相关指标
- `security_cpu_usage_total`: CPU 使用总量 (by_cpu, by_process)
- `security_syscall_count_total`: 系统调用总数 (by_syscall, by_process)
- `security_syscall_duration_seconds`: 系统调用耗时 (by_syscall, by_process)

### 进程相关指标
- `security_process_count_active`: 活跃进程数 (by_state, by_user)
- `security_process_events_total`: 进程事件数 (by_type, by_process)
- `security_process_exec_total`: 进程执行总数 (by_path, by_user)
- `security_process_memory_bytes`: 进程内存使用 (by_process, by_memory_type)

### 网络相关指标
- `security_network_connections_total`: 网络连接总数 (by_protocol, by_state)
- `security_network_bytes_in_total`: 网络入站字节数 (by_protocol, by_port)
- `security_network_bytes_out_total`: 网络出站字节数 (by_protocol, by_port)
- `security_network_packets_total`: 网络包总数 (by_protocol, by_direction)

### 文件系统相关指标
- `security_file_access_count_total`: 文件访问总数 (by_file_type, by_access_type)
- `security_file_bytes_read_total`: 文件读取字节数 (by_file, by_process)
- `security_file_bytes_written_total`: 文件写入字节数 (by_file, by_process)
- `security_file_open_handles`: 文件打开句柄数 (by_file_type, by_process)

### 安全相关指标
- `security_events_total`: 安全事件总数 (by_type, by_severity)
- `security_denied_access_total`: 访问拒绝总数 (by_path, by_user, by_reason)
- `security_failed_logins_total`: 登录失败总数 (by_user, by_service)
- `security_firewall_rules`: 防火墙规则统计 (by_chain, by_action)
- `security_audit_events_total`: 审计事件总数 (by_event_type, by_user)

### 系统相关指标
- `security_system_calls_per_second`: 每秒系统调用数 (by_syscall)
- `security_memory_usage_bytes`: 系统内存使用 (by_memory_type)
- `security_disk_usage_bytes`: 磁盘使用情况 (by_mount, by_filesystem)
- `security_load_average`: 系统负载平均值 (by_metric_type)

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

```
internal/
├── bpf/
│   ├── programs/
│   │   ├── syscall_tracer.bpf.c    # 系统调用追踪
│   │   ├── process_tracer.bpf.c     # 进程生命周期追踪
│   │   ├── network_tracer.bpf.c     # 网络连接追踪
│   │   ├── filesystem_tracer.bpf.c  # 文件系统访问追踪
│   │   └── security_tracer.bpf.c    # 安全事件追踪
│   ├── maps/
│   │   ├── syscall_stats.h         # 系统调用统计Map
│   │   ├── process_events.h         # 进程事件Map
│   │   ├── network_stats.h         # 网络统计Map
│   │   ├── file_access.h           # 文件访问Map
│   │   └── security_events.h        # 安全事件Map
│   └── lib/
│       ├── bpf_utils.h            # BPF 通用工具
│       ├── aggregation.h          # 聚合算法
│       └── ringbuffer.h           # Ring Buffer 处理
└── ebpf/
    ├── collector/
    │   ├── bpf_collector.go        # BPF 数据收集器
    │   ├── map_reader.go           # BPF Map 读取器
    │   ├── aggregator.go          # 数据聚合器
    │   └── metrics_exporter.go     # 指标导出器
    ├── programs/
    │   ├── program_loader.go       # BPF 程序加载器
    │   ├── program_config.go        # 程序配置
    │   └── program_manager.go      # 程序管理器
    └── config/
        ├── bpf_config.go           # BPF 配置管理
        └── resource_limits.go     # 资源限制配置
```

### 文件说明

- **`internal/bpf/`**: 内核态 BPF 程序代码
  - `programs/`: 5 个主要追踪程序
  - `maps/`: Map 结构定义和接口
  - `lib/`: 通用工具和算法

- **`internal/ebpf/`**: 用户态 Go 代码
  - `collector/`: 数据收集和聚合逻辑
  - `programs/`: BPF 程序管理
  - `config/`: 配置和资源管理