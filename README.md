# Security Collector Exporter

Linux 安全信息收集 Prometheus Exporter，用于监控服务器安全状态。采集账户、SSH、防火墙、端口、服务、补丁、进程等安全指标，支持 eBPF 实时安全事件监控。

## 快速开始

### 构建和运行

#### 本地构建

```bash
# 构建
go build -o security-exporter ./cmd/security-exporter

# 运行
./security-exporter --web.listen-address=:9102 --web.telemetry-path=/metrics
```

#### Docker 部署

```bash
# 构建 Docker 镜像
make docker-build

# 运行 Docker 容器（需要特权模式以读取系统文件）
make docker-run

# 或使用 docker-compose
docker-compose up -d
```

#### Systemd 部署（生产推荐）

```bash
# 1. 部署二进制
sudo cp security-exporter /usr/local/bin/

# 2. 创建 systemd 服务
sudo cat > /etc/systemd/system/security-exporter.service << 'EOF'
[Unit]
Description=Security Collector Exporter
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/security-exporter --web.listen-address=:9102
Restart=on-failure
RestartSec=5

# 需要读取 /etc/shadow, /proc 等系统文件
AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE

[Install]
WantedBy=multi-user.target
EOF

# 3. 启动服务
sudo systemctl daemon-reload
sudo systemctl enable --now security-exporter

# 验证
curl -s localhost:9102/metrics | head
```

### 配置参数

#### 基本配置

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--web.listen-address` | `:9102` | Web服务监听地址 |
| `--web.telemetry-path` | `/metrics` | Metrics暴露路径 |
| `--version` | - | 显示版本信息并退出 |

#### 端口状态配置

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--collector.port-states` | `LISTEN` | 要采集的TCP端口状态，多个状态用逗号分隔 |

#### 收集器配置

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--collector.go-metrics` | `false` | 是否采集Go自身性能指标（go_*指标），默认禁用 |
| `--collector.services-enabled` | `true` | 是否只采集启用的服务，默认true（只采集is_enabled=true的服务） |
| `--collector.services-running` | `false` | 是否只采集运行中的服务，默认false（不过滤运行状态） |

#### 日志配置

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--log.level` | `info` | 日志级别：debug, info, warn, error |
| `--log.format` | `logfmt` | 日志格式：logfmt, json |

#### eBPF 安全事件监控配置

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--ebpf.enabled` | `false` | 是否启用 eBPF 安全事件监控（需要 Linux 5.4+，需要特权） |
| `--ebpf.sample-rate` | `1` | eBPF 事件采样率（1=每个事件，10=每10个事件取1个） |
| `--ebpf.detailed` | `false` | 是否启用详细模式（Ring Buffer + Top-N 跟踪，资源消耗更高） |
| `--ebpf.max-events-per-second` | `5000` | 每秒最大事件数，超过后自适应降采样 |

#### 使用示例

```bash
# 基本运行
./security-exporter

# 自定义端口状态
./security-exporter --collector.port-states="LISTEN,ESTABLISHED"

# 开启调试模式
./security-exporter --log.level=debug

# 使用JSON日志格式
./security-exporter --log.level=info --log.format=json

# 启用Go自身性能指标采集
./security-exporter --collector.go-metrics

# 采集所有服务（包括未启用和未运行的服务）
./security-exporter --collector.services-enabled=false

# 只采集运行中的服务
./security-exporter --collector.services-running=true

# 只采集既启用又运行的服务
./security-exporter --collector.services-enabled=true --collector.services-running=true

# 启用 eBPF 安全事件监控（需 Linux 5.4+ 及特权模式）
./security-exporter --ebpf.enabled=true

# 启用 eBPF + 详细模式（Ring Buffer + Top-N，资源消耗更高）
./security-exporter --ebpf.enabled=true --ebpf.detailed=true

# 启用 eBPF + 自定义采样率
./security-exporter --ebpf.enabled=true --ebpf.sample-rate=10 --ebpf.max-events-per-second=10000
```

## 项目结构

```
security-collector-exporter/
├── cmd/security-exporter/     # 入口，HTTP server + Prometheus 注册
├── internal/
│   ├── bpf/                 # eBPF BPF C 程序 + Go 绑定
│   │   ├── sources/         # BPF C 源文件
│   │   ├── bpf2go.go        # go:generate 指令
│   │   └── types.go         # BPF 常量 Go 绑定
│   ├── collector/            # Prometheus collector
│   │   ├── security_collector.go  # 传统安全指标采集
│   │   └── ebpf_collector.go     # eBPF 指标采集
│   ├── ebpf/                 # eBPF Go 集成层
│   │   ├── manager.go       # 生命周期管理
│   │   ├── aggregator.go    # BPF Map 聚合读取器
│   │   ├── spacesaving.go   # Space-Saving Top-N
│   │   ├── sampler.go       # 自适应采样
│   │   └── fallback.go      # 优雅降级
│   └── system/               # 核心采集逻辑（12 文件）
│       ├── account_info.go   # 账户/shadow
│       ├── network_info.go   # 端口/防火墙
│       ├── process_info.go   # 进程版本探测
│       ├── config_info.go    # SSH/SELinux 配置
│       └── ...
├── pkg/
│   ├── config/              # CLI flags + 版本注入
│   └── logger/              # 日志封装
├── doc/                      # 文档
├── Makefile
├── Dockerfile
└── docker-compose.yml
```

## 监控指标

收集器提供以下安全相关指标：

### 基础系统信息
- `linux_security_os_version_info`: 操作系统版本信息
- `linux_security_account_info`: 系统账户信息（passwd文件信息）
- `linux_security_sshd_config_info`: SSH服务配置信息

### 密码策略指标
- `linux_security_last_password_change`: 最后密码修改时间（天数）
- `linux_security_password_max_days`: 密码最大有效期（天数）
- `linux_security_password_min_days`: 密码最小有效期（天数）
- `linux_security_password_warn_days`: 密码警告天数
- `linux_security_password_inactive`: 密码不活跃天数
- `linux_security_account_expire`: 账户过期时间（天数）

### 密码策略检查
- `linux_security_login_defs_info`: login.defs配置信息

### 系统安全配置
- `linux_security_selinux_config`: SELinux配置信息
- `linux_security_firewall_enabled`: 防火墙是否启用（包含防火墙类型和运行状态）
  - 支持类型：firewalld、ufw、iptables、nftables
- `linux_security_ports_use_info`: 系统端口使用信息（包含协议、IP、端口、状态、进程名、可执行路径、版本、应用名称）
  - 协议：tcp、tcp6、udp、udp6
  - TCP状态：LISTEN、ESTABLISHED、SYN_SENT、SYN_RECV、FIN_WAIT1、FIN_WAIT2、TIME_WAIT、CLOSE、CLOSE_WAIT、LAST_ACK、CLOSING
- `linux_security_hosts_options_info`: hosts.deny和hosts.allow配置信息

### 系统服务检查
- `linux_security_services_info`: 系统服务信息
- `linux_security_system_target_info`: 系统目标信息

### 系统维护
- `linux_security_last_patch_time`: 最后一次补丁时间
  - 支持包管理器类型：rpm（RedHat/CentOS）、dpkg（Debian/Ubuntu）、pacman（Arch Linux）
- `linux_security_package_count`: 已安装包数量
  - 支持包管理器类型：rpm（RedHat/CentOS）、dpkg（Debian/Ubuntu）、pacman（Arch Linux）

### eBPF 安全事件监控（需 --ebpf.enabled=true）

#### 元信息
- `security_ebpf_up`: eBPF 监控状态（status 标签：active/degraded/disabled）
- `security_ebpf_sample_rate`: 当前采样率

#### 进程指标（type 标签：system/user/container/suspicious）
- `security_ebpf_process_exec_total`: 进程执行次数
- `security_ebpf_process_exit_total`: 进程退出次数
- `security_ebpf_process_active_count`: 活跃进程数

#### 网络指标
- `security_ebpf_connect_total`: 网络连接总数（direction×protocol，基数 4）
- `security_ebpf_connect_active`: 当前活跃连接数
- `security_ebpf_connect_error_total`: 连接错误数（type 标签：timeout/refused/reset）

#### 文件访问（severity×operation，基数 6）
- `security_ebpf_file_access_total`: 敏感文件访问次数

#### 提权检测（type×result，基数 6）
- `security_ebpf_privilege_escalation_total`: 提权尝试次数

#### 内核模块（action 标签，基数 2）
- `security_ebpf_kernel_module_total`: 内核模块操作次数


## 文档

- [快速开始指南](doc/QUICK_START.md) - 构建、运行和基本配置指南
- [安全标准检查清单](doc/SECURITY_CHECKLIST.md) - 详细的安全检查项目和PromQL查询示例
- [Prometheus查询示例](doc/SECURITY_CHECKLIST.md#prometheus查询示例) - 各种安全指标的查询方法
- [告警规则示例](doc/SECURITY_CHECKLIST.md#告警规则示例) - 基于安全指标的告警配置
- [eBPF 架构设计](doc/ebpf-architecture.md) - eBPF 集成架构设计文档
- [eBPF 部署指南](doc/ebpf-deployment.md) - 内核要求、部署和故障排查

## 安全标准合规性

本收集器基于Linux安全配置标准设计，检查以下关键安全要求：

1. **账户管理**：检查账户创建、权限配置
2. **密码策略**：验证密码复杂度、有效期、锁定策略
3. **系统配置**：检查SELinux、防火墙、TCP Wrappers配置
4. **服务管理**：识别不必要的服务和账户
5. **系统维护**：监控补丁更新状态

## 使用示例

### 基本查询

```promql
# 检查SSH配置
linux_security_sshd_config_info{info_key="PermitRootLogin", info_value="no"}

# 检查SELinux状态
linux_security_selinux_config{info_key="SELINUX", info_value="enforcing"}

# 检查防火墙状态（已启用且正在运行）
linux_security_firewall_enabled{firewall_type="firewalld", is_running="true"} == 1

# 检查端口使用情况
linux_security_ports_use_info{process="sshd", port="22"}

# 检查密码策略
linux_security_login_defs_info{info_key="PASS_MIN_LEN", info_value="num"} >= 10

### eBPF 安全事件查询

```promql
# eBPF 监控状态
security_ebpf_up

# 进程执行次数（按类型）
security_ebpf_process_exec_total

# 活跃进程数
security_ebpf_process_active_count

# 网络连接统计
security_ebpf_connect_total

# 网络连接错误
security_ebpf_connect_error_total

# 敏感文件访问
security_ebpf_file_access_total

# 提权尝试
security_ebpf_privilege_escalation_total

# 内核模块操作
security_ebpf_kernel_module_total

# 当前采样率
security_ebpf_sample_rate
```


更多详细的配置说明、查询示例和告警规则，请参考：
- [快速开始指南](doc/QUICK_START.md) - 详细的配置和运行说明
- [安全标准检查清单](doc/SECURITY_CHECKLIST.md) - 完整的查询示例和告警规则