# Security Collector Exporter - Code Wiki

## 目录
- [项目概述](#项目概述)
- [架构设计](#架构设计)
- [目录结构](#目录结构)
- [核心模块详解](#核心模块详解)
- [主要类与函数](#主要类与函数)
- [依赖关系](#依赖关系)
- [构建与部署](#构建与部署)

---

## 项目概述

### 项目简介
Security Collector Exporter 是一个 Linux 安全信息 Prometheus Exporter，提供全面的服务器安全监控能力。它通过传统系统调用和 eBPF 技术结合，实现对系统安全状态的全面监控。

### 主要特性
- **全面安全指标监控**：账户、SSH、防火墙、端口、服务、补丁、进程
- **实时 eBPF 监控**：基于 5 个 BPF 程序和 14 个内核 tracepoint
- **Prometheus 原生集成**
- **多种部署方式**：二进制、Docker、Systemd
- **自适应采样与优雅降级**

---

## 架构设计

### 整体架构

```
┌───────────────────────────────────────────────────────────────────────┐
│                          Security Exporter                              │
├───────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌───────────────────────────┐      ┌───────────────────────────┐     │
│  │   Traditional Collector   │      │     eBPF Collector        │     │
│  │  (System Info Scanning)   │      │   (Real-time Monitoring)  │     │
│  └───────────────────────────┘      └───────────────────────────┘     │
│              │                                  │                      │
│              └───────────────┬──────────────────┘                      │
│                              │                                         │
│                    ┌─────────▼──────────┐                             │
│                    │   Prometheus       │                             │
│                    │   Collector        │                             │
│                    └─────────┬──────────┘                             │
│                              │                                         │
│                    ┌─────────▼──────────┐                             │
│                    │   HTTP Server      │                             │
│                    │   (:9102/metrics)  │                             │
│                    └────────────────────┘                             │
│                                                                         │
└───────────────────────────────────────────────────────────────────────┘
```

### eBPF 架构

```
┌───────────────────────────────────────────────────────────────────────┐
│                          User Space                                    │
├───────────────────────────────────────────────────────────────────────┤
│  ┌──────────┐    ┌───────────┐    ┌───────────┐    ┌───────────┐    │
│  │  Manager │───▶│Aggregator │───▶│ Collector  │───▶│ HTTP API  │    │
│  └──────────┘    └───────────┘    └───────────┘    └───────────┘    │
└───────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────────────┐
│                         Kernel Space                                  │
├───────────────────────────────────────────────────────────────────────┤
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐        │
│  │ Process │ │ Network │ │  File   │ │Privilege│ │ Kernel  │        │
│  │   BPF   │ │   BPF   │ │   BPF   │ │   BPF   │ │   BPF   │        │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘        │
│       │           │           │           │           │              │
│       └───────────┴───────────┴───────────┴───────────┘              │
│                              ▼                                        │
│                      Tracepoints & Kprobes                            │
└───────────────────────────────────────────────────────────────────────┘
```

---

## 目录结构

```
security-collector-exporter/
├── cmd/
│   └── security-exporter/          # 入口程序
│       └── main.go
├── internal/
│   ├── bpf/                        # eBPF 程序和 Go 绑定
│   │   ├── sources/                # BPF C 源代码
│   │   │   ├── process.c
│   │   │   ├── network.c
│   │   │   ├── file.c
│   │   │   ├── privilege.c
│   │   │   └── kernel.c
│   │   ├── bpf2go.go               # go:generate 指令
│   │   └── types.go
│   ├── collector/                  # Prometheus 指标收集器
│   │   ├── security_collector.go   # 传统安全指标收集器
│   │   └── ebpf_collector.go       # eBPF 指标收集器
│   ├── ebpf/                       # eBPF 集成层
│   │   ├── manager.go              # eBPF 生命周期管理
│   │   ├── aggregator.go           # BPF Maps 聚合器
│   │   ├── sampler.go              # 自适应采样器
│   │   ├── spacesaving.go          # Space-Saving 算法
│   │   └── fallback.go             # 优雅降级机制
│   └── system/                     # 系统信息采集模块
│       ├── account_info.go
│       ├── network_info.go
│       ├── process_info.go
│       ├── config_info.go
│       ├── auditd_info.go
│       ├── selinux_detail_info.go
│       └── ...
├── pkg/
│   ├── config/                     # 配置管理
│   │   └── config.go
│   └── logger/                     # 日志封装
│       └── logger.go
├── docs/                           # 文档目录
│   ├── zh/                         # 中文文档
│   └── en/                         # 英文文档
├── .github/                        # GitHub 工作流
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── go.mod
└── go.sum
```

---

## 核心模块详解

### 1. 入口模块 (cmd/security-exporter)

**文件**：[main.go](file:///workspace/cmd/security-exporter/main.go)

**职责**：
- 初始化配置和日志系统
- 启动 HTTP 服务器
- 注册 Prometheus 收集器
- 管理 eBPF 生命周期
- 处理优雅关闭

**主要流程**：
```go
func main() {
    // 1. 加载配置
    cfg := config.LoadConfig()
    
    // 2. 初始化安全收集器
    securityCollector := collector.NewSecurityCollector(cfg)
    prometheus.MustRegister(securityCollector)
    
    // 3. 初始化 eBPF 管理器
    ebpfManager := ebpf.NewManager(cfg)
    ebpfManager.Start(ctx)
    
    // 4. 初始化 eBPF 收集器
    ebpfCollector := collector.NewEbpfCollector(...)
    prometheus.MustRegister(ebpfCollector)
    
    // 5. 启动 HTTP 服务器
    http.ListenAndServe(cfg.ListenAddress, nil)
}
```

---

### 2. 配置模块 (pkg/config)

**文件**：[config.go](file:///workspace/pkg/config/config.go)

**核心结构**：
```go
type Config struct {
    ListenAddress          string  // HTTP 监听地址
    MetricsPath            string  // Metrics 暴露路径
    PortStates             []string // 要收集的端口状态
    LogLevel               string  // 日志级别
    LogFormat              string  // 日志格式
    EnableGoMetrics        bool    // 是否收集 Go 性能指标
    CollectServicesEnabled bool    // 是否只收集启用的服务
    CollectServicesRunning bool    // 是否只收集运行中的服务
    EbpfEnabled            bool    // 是否启用 eBPF
    EbpfSampleRate         int     // eBPF 采样率
    EbpfDetailed           bool    // eBPF 详细模式
    EbpfMaxEventsPerSec    int     // 每秒最大事件数
}
```

**主要函数**：
- `LoadConfig()` - 解析命令行参数并加载配置
- `PrintVersion()` - 打印版本信息

---

### 3. 收集器模块 (internal/collector)

#### SecurityCollector (传统安全指标收集器)

**文件**：[security_collector.go](file:///workspace/internal/collector/security_collector.go)

**职责**：
- 收集系统安全相关的 Prometheus 指标
- 实现 `prometheus.Collector` 接口

**核心方法**：
| 方法 | 描述 |
|------|------|
| `NewSecurityCollector()` | 创建安全收集器实例 |
| `Describe()` | 描述所有指标 |
| `Collect()` | 收集所有指标（主入口） |
| `collectOSInfo()` | 收集系统版本信息 |
| `collectAccountInfo()` | 收集系统账户信息 |
| `collectShadowInfo()` | 收集密码策略指标 |
| `collectSSHConfig()` | 收集 SSH 配置信息 |
| `collectFirewallStatus()` | 收集防火墙状态 |
| `collectPortsInfo()` | 收集端口使用信息 |
| `collectServicesInfo()` | 收集服务信息 |

**收集的指标**：
- `linux_security_os_version_info` - 操作系统版本
- `linux_security_account_info` - 系统账户信息
- `linux_security_last_password_change` - 最后密码修改时间
- `linux_security_sshd_config_info` - SSH 配置
- `linux_security_selinux_config` - SELinux 配置
- `linux_security_firewall_enabled` - 防火墙状态
- `linux_security_ports_use_info` - 端口使用信息
- `linux_security_services_info` - 系统服务信息
- `linux_security_last_patch_time` - 最后补丁时间
- 等等...

#### EbpfCollector (eBPF 指标收集器)

**文件**：[ebpf_collector.go](file:///workspace/internal/collector/ebpf_collector.go)

**职责**：
- 收集 eBPF 监控的安全事件指标
- 实现 `prometheus.Collector` 接口

**核心方法**：
| 方法 | 描述 |
|------|------|
| `NewEbpfCollector()` | 创建 eBPF 收集器实例 |
| `Describe()` | 描述所有指标 |
| `Collect()` | 从 Aggregator 读取并收集指标 |

**eBPF 指标**：
- `security_ebpf_up` - eBPF 监控状态
- `security_ebpf_sample_rate` - 当前采样率
- `security_ebpf_process_exec_total` - 进程执行次数
- `security_ebpf_process_exit_total` - 进程退出次数
- `security_ebpf_process_active_count` - 活跃进程数
- `security_ebpf_connect_total` - 网络连接总数
- `security_ebpf_connect_error_total` - 连接错误数
- `security_ebpf_file_access_total` - 敏感文件访问次数
- `security_ebpf_privilege_escalation_total` - 提权尝试次数
- `security_ebpf_kernel_module_total` - 内核模块操作次数

---

### 4. eBPF 模块 (internal/ebpf)

#### Manager (eBPF 管理器)

**文件**：[manager.go](file:///workspace/internal/ebpf/manager.go)

**职责**：
- 管理 eBPF 程序的完整生命周期
- 检查 BPF 可用性
- 加载 BPF 程序到内核
- 附加 tracepoints/kprobes
- 启动 BPF map 读取循环

**核心结构**：
```go
type Manager struct {
    enabled    bool
    running    bool
    aggregator *Aggregator
    sampler    *AdaptiveSampler
    // BPF 对象
    processObjs   bpf.BpfProcessObjects
    networkObjs   bpf.BpfNetworkObjects
    fileObjs      bpf.BpfFileObjects
    privilegeObjs bpf.BpfPrivilegeObjects
    kernelObjs    bpf.BpfKernelObjects
    links         []link.Link
}
```

**核心方法**：
| 方法 | 描述 |
|------|------|
| `NewManager()` | 创建 Manager 实例 |
| `Start()` | 启动 eBPF 监控 |
| `Stop()` | 停止 eBPF 监控 |
| `loadBpfPrograms()` | 加载所有 BPF 程序 |
| `attachTracepoints()` | 附加 tracepoints |
| `startMapReaderLoop()` | 启动周期性 map 读取 |
| `IsRunning()` | 检查是否正在运行 |
| `Enabled()` | 检查是否已启用 |
| `SampleRate()` | 获取当前采样率 |

**启动流程**：
1. 检查 BPF 可用性
2. 提升内存锁限制
3. 加载 5 个 BPF 程序
4. 附加 14 个 tracepoints
5. 注入 BPF maps 到 Aggregator
6. 启动周期性 map 读取 goroutine

#### Aggregator (BPF Map 聚合器)

**文件**：[aggregator.go](file:///workspace/internal/ebpf/aggregator.go)

**职责**：
- 从 BPF per-cpu maps 读取并聚合数据
- 提供各类统计数据的读取接口

**核心方法**：
| 方法 | 描述 |
|------|------|
| `NewAggregator()` | 创建聚合器实例 |
| `SetMaps()` | 设置 BPF maps |
| `ReadAndUpdateFromMaps()` | 从 BPF maps 读取并更新统计 |
| `ReadProcessStats()` | 读取进程统计 |
| `ReadNetworkStats()` | 读取网络统计 |
| `ReadFileStats()` | 读取文件访问统计 |
| `ReadPrivilegeStats()` | 读取提权统计 |
| `ReadKernelStats()` | 读取内核模块统计 |

#### AdaptiveSampler (自适应采样器)

**文件**：[sampler.go](file:///workspace/internal/ebpf/sampler.go)

**职责**：
- 根据事件负载动态调整采样率
- 防止系统过载

#### SpaceSaving (Space-Saving 算法)

**文件**：[spacesaving.go](file:///workspace/internal/ebpf/spacesaving.go)

**职责**：
- 实现 Space-Saving Top-N 算法
- 用于追踪热点事件

#### Fallback (优雅降级机制)

**文件**：[fallback.go](file:///workspace/internal/ebpf/fallback.go)

**职责**：
- 检测 BPF 环境可用性
- 当 eBPF 不可用时自动降级到传统模式

---

### 5. BPF 模块 (internal/bpf)

**文件**：
- [bpf2go.go](file:///workspace/internal/bpf/bpf2go.go) - go:generate 指令
- [types.go](file:///workspace/internal/bpf/types.go) - 类型定义
- [sources/process.c](file:///workspace/internal/bpf/sources/process.c) - 进程监控 BPF 程序
- [sources/network.c](file:///workspace/internal/bpf/sources/network.c) - 网络监控 BPF 程序
- [sources/file.c](file:///workspace/internal/bpf/sources/file.c) - 文件访问监控 BPF 程序
- [sources/privilege.c](file:///workspace/internal/bpf/sources/privilege.c) - 提权监控 BPF 程序
- [sources/kernel.c](file:///workspace/internal/bpf/sources/kernel.c) - 内核模块监控 BPF 程序

**BPF 程序说明**：

| 程序 | Tracepoints | 功能 |
|------|-------------|------|
| Process | `sys_enter_execve`, `sched_process_exit` | 监控进程创建和退出 |
| Network | `inet_sock_set_state` | 监控 TCP 连接状态变化 |
| File | `sys_enter_openat` | 监控敏感文件访问 |
| Privilege | `sys_enter/exit_setuid`, `sys_enter/exit_setgid`, `sys_enter/exit_capset` | 监控提权操作 |
| Kernel | `sys_enter_init_module`, `sys_enter_finit_module` | 监控内核模块加载 |

---

### 6. 系统信息采集模块 (internal/system)

**核心文件**：

| 文件 | 功能 |
|------|------|
| [account_info.go](file:///workspace/internal/system/account_info.go) | 账户和密码信息采集 |
| [network_info.go](file:///workspace/internal/system/network_info.go) | 网络和端口信息采集 |
| [process_info.go](file:///workspace/internal/system/process_info.go) | 进程信息采集 |
| [config_info.go](file:///workspace/internal/system/config_info.go) | SSH/SELinux 配置采集 |
| [auditd_info.go](file:///workspace/internal/system/auditd_info.go) | Auditd 信息采集 |
| [selinux_detail_info.go](file:///workspace/internal/system/selinux_detail_info.go) | SELinux 详细信息 |
| [service_info.go](file:///workspace/internal/system/service_info.go) | 系统服务信息采集 |
| [system_info.go](file:///workspace/internal/system/system_info.go) | 系统版本和补丁信息 |

---

## 主要类与函数

### 核心类/结构体

#### 1. SecurityCollector
```go
type SecurityCollector struct {
    config *config.Config
    // 各种指标描述符
    osVersionInfo          *prometheus.Desc
    accountInfo            *prometheus.Desc
    lastPasswordChange     *prometheus.Desc
    // ... 更多指标
}
```

#### 2. EbpfCollector
```go
type EbpfCollector struct {
    mu         sync.Mutex
    aggregator *ebpf.Aggregator
    enabled    bool
    running    bool
    // 指标描述符
    processExecTotal   *prometheus.Desc
    connectTotal       *prometheus.Desc
    // ... 更多指标
}
```

#### 3. Manager
```go
type Manager struct {
    enabled    bool
    running    bool
    aggregator *Aggregator
    sampler    *AdaptiveSampler
    // BPF 对象
    processObjs   bpf.BpfProcessObjects
    networkObjs   bpf.BpfNetworkObjects
    // ... 更多 BPF 对象
    links         []link.Link
}
```

#### 4. Aggregator
```go
type Aggregator struct {
    mu         sync.RWMutex
    maps       *BpfMaps
    process    ProcessStats
    network    NetworkStats
    file       FileStats
    privilege  PrivilegeStats
    kernel     KernelStats
}
```

#### 5. Config
```go
type Config struct {
    ListenAddress          string
    MetricsPath            string
    PortStates             []string
    // ... 更多配置
}
```

---

## 依赖关系

### Go 模块依赖

**文件**：[go.mod](file:///workspace/go.mod)

| 依赖 | 版本 | 用途 |
|------|------|------|
| `github.com/prometheus/client_golang` | v1.23.2 | Prometheus 客户端库 |
| `github.com/cilium/ebpf` | v0.21.0 | eBPF 程序加载库 |
| `github.com/prometheus/common` | (indirect) | Prometheus 通用工具 |
| `github.com/prometheus/procfs` | (indirect) | /proc 文件系统访问 |
| `golang.org/x/sys` | (indirect) | 系统调用封装 |
| `google.golang.org/protobuf` | (indirect) | Protocol Buffers |

### 模块依赖关系图

```
main (cmd/security-exporter)
├── config (pkg/config)
├── logger (pkg/logger)
├── collector (internal/collector)
│   ├── system (internal/system)
│   ├── config (pkg/config)
│   └── ebpf (internal/ebpf)
│       ├── bpf (internal/bpf)
│       ├── config (pkg/config)
│       └── logger (pkg/logger)
└── prometheus/client_golang
```

---

## 构建与部署

### 构建流程

**Makefile 目标**：[Makefile](file:///workspace/Makefile)

| 目标 | 描述 |
|------|------|
| `make build` | 构建二进制 |
| `make test` | 运行测试 |
| `make lint` | 运行代码检查 |
| `make fmt` | 格式化代码 |
| `make bpf-generate` | 生成 BPF Go 绑定（需要 Docker） |
| `make docker-build` | 构建 Docker 镜像 |
| `make docker-run` | 运行 Docker 容器 |

### 构建命令

#### 1. 本地构建
```bash
# 生成 BPF Go 绑定
go generate ./internal/bpf/...

# 构建应用
go build -o security-exporter ./cmd/security-exporter
```

#### 2. Docker 构建
```bash
# 使用 Makefile
make docker-build

# 或直接使用 Docker
docker build -t security-exporter:latest .
```

#### 3. 完整构建（包含 BPF）
```bash
make bpf-build
```

### 运行方式

#### 1. 二进制运行
```bash
./security-exporter --web.listen-address=:9102
```

#### 2. Docker 运行
```bash
docker run -d --name security-exporter -p 9102:9102 --privileged security-exporter:latest
```

#### 3. Docker Compose
```bash
docker-compose up -d
```

#### 4. Systemd 部署（生产环境推荐）
```bash
# 创建服务文件
cat > /etc/systemd/system/security-exporter.service << 'EOF'
[Unit]
Description=Security Collector Exporter
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/security-exporter --web.listen-address=:9102
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE

[Install]
WantedBy=multi-user.target
EOF

# 启动服务
sudo systemctl daemon-reload
sudo systemctl enable --now security-exporter
```

### 配置参数

| 参数 | 默认值 | 描述 |
|------|--------|------|
| `--web.listen-address` | `:9102` | HTTP 监听地址 |
| `--web.telemetry-path` | `/metrics` | Metrics 路径 |
| `--collector.port-states` | `LISTEN` | 要收集的端口状态 |
| `--log.level` | `info` | 日志级别 |
| `--log.format` | `logfmt` | 日志格式 |
| `--ebpf.enabled` | `false` | 启用 eBPF 监控 |
| `--ebpf.sample-rate` | `1` | eBPF 采样率 |
| `--version` | - | 显示版本信息 |

### 系统要求

- **操作系统**：Linux
- **内核版本**：5.4+ (eBPF 功能)
- **Go 版本**：1.26+
- **权限要求**：
  - 读取系统文件（如 /etc/shadow, /proc）
  - eBPF 功能需要 CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN 或 --privileged

---

## 指标说明

### 传统安全指标

| 指标名称 | 类型 | 描述 |
|----------|------|------|
| `linux_security_os_version_info` | Gauge | 操作系统版本信息 |
| `linux_security_account_info` | Gauge | 系统账户信息 |
| `linux_security_last_password_change` | Gauge | 最后密码修改时间 |
| `linux_security_password_max_days` | Gauge | 密码最大有效期 |
| `linux_security_sshd_config_info` | Gauge | SSH 配置信息 |
| `linux_security_selinux_config` | Gauge | SELinux 配置 |
| `linux_security_firewall_enabled` | Gauge | 防火墙状态 |
| `linux_security_ports_use_info` | Gauge | 端口使用信息 |
| `linux_security_services_info` | Gauge | 服务信息 |
| `linux_security_last_patch_time` | Gauge | 最后补丁时间 |
| `linux_security_package_count` | Gauge | 已安装包数量 |

### eBPF 安全指标

| 指标名称 | 类型 | 描述 |
|----------|------|------|
| `security_ebpf_up` | Gauge | eBPF 监控状态 |
| `security_ebpf_sample_rate` | Gauge | 当前采样率 |
| `security_ebpf_process_exec_total` | Counter | 进程执行次数 |
| `security_ebpf_process_exit_total` | Counter | 进程退出次数 |
| `security_ebpf_process_active_count` | Gauge | 活跃进程数 |
| `security_ebpf_connect_total` | Counter | 网络连接总数 |
| `security_ebpf_connect_error_total` | Counter | 连接错误数 |
| `security_ebpf_file_access_total` | Counter | 敏感文件访问次数 |
| `security_ebpf_privilege_escalation_total` | Counter | 提权尝试次数 |
| `security_ebpf_kernel_module_total` | Counter | 内核模块操作次数 |

---

*本 Code Wiki 最后更新于 2026-06-01*
