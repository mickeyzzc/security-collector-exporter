# Security Collector

Linux安全信息收集器，用于Prometheus监控系统安全状态。

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

# 运行 Docker 容器
make docker-run

# 或使用 docker-compose
docker-compose up -d

# 停止容器
make docker-stop
# 或
docker-compose down
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

#### 日志配置

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--log.level` | `info` | 日志级别：debug, info, warn, error |
| `--log.format` | `logfmt` | 日志格式：logfmt, json |

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
```

## 项目结构

```
Security-Collector/
├── cmd/security-exporter/     # 主程序入口
│   └── main.go
├── internal/                  # 内部包
│   ├── collector/            # Prometheus收集器
│   │   └── security_collector.go
│   └── system/               # 系统检查功能
│       ├── account_info.go   # 账户信息检查
│       ├── config_info.go    # 配置文件检查
│       ├── network_info.go   # 网络信息检查
│       ├── os_info.go        # 操作系统信息
│       ├── service_info.go   # 服务信息检查
│       ├── system_info.go    # 系统信息检查
│       └── utils.go          # 工具函数
├── pkg/                      # 公共包
│   ├── config/              # 配置管理
│   │   └── config.go
│   └── logger/              # 日志管理
│       └── logger.go
├── doc/                      # 文档目录
│   ├── QUICK_START.md       # 快速开始指南
│   └── SECURITY_CHECKLIST.md # 安全标准检查清单
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
└── README.md
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
- `linux_security_ports_use_info`: 系统端口使用信息（包含进程名）
- `linux_security_hosts_options_info`: hosts.deny和hosts.allow配置信息

### 系统服务检查
- `linux_security_services_info`: 系统服务信息
- `linux_security_system_target_info`: 系统目标信息

### 系统维护
- `linux_security_last_patch_time`: 最后一次补丁时间
- `linux_security_package_count`: 已安装包数量

## 文档

- [快速开始指南](doc/QUICK_START.md) - 构建、运行和基本配置指南
- [安全标准检查清单](doc/SECURITY_CHECKLIST.md) - 详细的安全检查项目和PromQL查询示例
- [Prometheus查询示例](doc/SECURITY_CHECKLIST.md#prometheus查询示例) - 各种安全指标的查询方法
- [告警规则示例](doc/SECURITY_CHECKLIST.md#告警规则示例) - 基于安全指标的告警配置

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
```

更多详细的配置说明、查询示例和告警规则，请参考：
- [快速开始指南](doc/QUICK_START.md) - 详细的配置和运行说明
- [安全标准检查清单](doc/SECURITY_CHECKLIST.md) - 完整的查询示例和告警规则