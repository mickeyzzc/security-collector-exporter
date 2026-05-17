# PROJECT KNOWLEDGE BASE

**Generated:** 2026-05-12
**Commit:** 6dfe954
**Branch:** main

## OVERVIEW

Linux 安全信息收集 Prometheus Exporter。Go 1.26，唯一外部依赖 `prometheus/client_golang`。采集账户、SSH、防火墙、端口、服务、补丁、进程等安全指标。

## STRUCTURE

```
security-collector-exporter/
├── cmd/security-exporter/     # 入口，HTTP server + Prometheus 注册
├── internal/
│   ├── bpf/                 # eBPF BPF C 程序 + Go 绑定
│   │   ├── sources/         # BPF C 源文件
│   │   ├── bpf2go.go        # go:generate 指令
│   │   └── types.go         # BPF 常量 Go 绑定
│   ├── collector/             # SecurityCollector — Prometheus Describe/Collect
│   ├── ebpf/                  # eBPF Go 集成层
│   │   ├── manager.go        # 生命周期管理
│   │   ├── aggregator.go     # BPF Map 聚合读取器
│   │   ├── spacesaving.go    # Space-Saving Top-N
│   │   ├── sampler.go        # 自适应采样
│   │   └── fallback.go       # 优雅降级
│   └── system/               # 核心采集逻辑（12 文件，~5500 行）
│       ├── testdata/         # 测试数据
│       └── testutil/         # 测试工具包
├── pkg/
│   ├── config/               # CLI flags + 版本注入（ldflags）
│   └── logger/               # 简单日志封装
├── .github/workflows/        # CI/CD（ci.yml, release.yml）
├── doc/                      # 文档
├── Makefile                  # 构建/测试/Docker 目标
├── Dockerfile                # 多阶段构建，alpine
├── Dockerfile.goreleaser     # goreleaser 构建
├── .goreleaser.yml           # goreleaser 配置
├── .golangci.yml             # golangci-lint 配置
└── docker-compose.yml        # 需 --privileged + 系统文件挂载
```

## WHERE TO LOOK

| 任务 | 位置 | 备注 |
|------|------|------|
| 添加新指标 | `internal/system/*.go` → `internal/collector/security_collector.go` | 先写 Get 函数，再在 collector 注册 gauge |
| 修改 CLI 参数 | `pkg/config/config.go` | kingpin flags，LoadConfig() |
| 理解采集流程 | `internal/collector/security_collector.go:Collect()` | 调用 system 包各 Get 函数 |
| 端口/防火墙逻辑 | `internal/system/network_info.go` | 解析 /proc/net，检测 firewalld/ufw/iptables/nftables |
| 进程版本探测 | `internal/system/process_info.go` | 1347 行，含 Java 版本检测/容器检测/JAR 解析 |
| 账户/shadow | `internal/system/account_info.go` | 解析 /etc/passwd、/etc/shadow |
| 配置文件解析 | `internal/system/config_info.go` | SSH、login.defs、SELinux、hosts.deny |
| 调试日志 | `pkg/logger/logger.go` | `--log.level=debug` 开启 |
| 添加 eBPF 指标 | `internal/bpf/sources/*.c` → `internal/ebpf/aggregator.go` → `internal/collector/ebpf_collector.go` | 先写 BPF C 程序，再在 collector 注册 |

## CODE MAP

| Symbol | Type | Location | Role |
|--------|------|----------|------|
| `Config` | struct | pkg/config/config.go:14 | CLI 配置容器 |
| `LoadConfig` | func | pkg/config/config.go:49 | 解析 flags + 初始化日志 |
| `SecurityCollector` | struct | internal/collector/security_collector.go:14 | Prometheus collector，持有所有采集数据 |
| `NewSecurityCollector` | func | internal/collector/security_collector.go:67 | 构造器，调用 system 包初始化数据 |
| `Collect` | method | internal/collector/security_collector.go:240 | 核心采集循环，暴露所有 metrics |
| `GetAllAccountInfo` | func | internal/system/account_info.go:48 | 解析 /etc/passwd |
| `GetAllShadowInfo` | func | internal/system/account_info.go:284 | 解析 /etc/shadow |
| `CheckFirewallStatus` | func | internal/system/network_info.go:60 | 检测防火墙状态 |
| `GetPortsUseInfo` | func | internal/system/network_info.go:325 | 端口采集（解析 /proc/net/tcp） |
| `getProcessVersion` | func | internal/system/process_info.go:20 | 进程版本探测入口 |
| `GetAllServicesInfo` | func | internal/system/service_info.go:20 | 服务列表采集 |
| `GetPatchTimeInfo` | func | internal/system/system_info.go:25 | 最后补丁时间 |
| `GetSSHConfigInfo` | func | internal/system/config_info.go:17 | SSH 配置解析 |
| `Aggregator` | struct | internal/ebpf/aggregator.go | BPF Map 预聚合读取器 |
| `Manager` | struct | internal/ebpf/manager.go | eBPF 生命周期管理 |
| `EbpfCollector` | struct | internal/collector/ebpf_collector.go | Prometheus eBPF collector |
| `SpaceSaving` | struct | internal/ebpf/spacesaving.go | Top-N 频繁项追踪 |
| `AdaptiveSampler` | struct | internal/ebpf/sampler.go | 自适应采样控制器 |
| `CheckBPFAvailability` | func | internal/ebpf/fallback.go | BPF 可用性检测 |

## CONVENTIONS

- 采集函数统一用 `Get*` / `GetAll*` 命名，返回结构体切片或单结构体
- 每个采集域一个文件：`account_info.go`、`network_info.go` 等
- Prometheus 指标命名在 `security_collector.go` 中集中定义
- 版本信息通过 `-ldflags` 注入 `pkg/config` 包变量
- 日志使用 `pkg/logger` 封装，支持 logfmt/json 格式
- 注释使用中文
- BPF C 程序使用 percpu_array map 做内核预聚合，避免维度爆炸
- eBPF 指标前缀使用 `security_ebpf_*`，与现有 `linux_security_*` 区分
- 所有 eBPF 指标标签基数 ≤ 10

## ANTI-PATTERNS (THIS PROJECT)

- **无测试文件**：整个项目 0 个 `*_test.go`，`make test` 可运行但无测试。现已补充至 12 个测试文件（71 个测试函数）
- **无 CI/CD**：无 GitHub Actions / GitLab CI 配置。已配置（`.github/workflows/ci.yml` + `release.yml`）
- **Go 版本不一致**：`go.mod` 指定 1.24，`Dockerfile` 使用 golang:1.21-alpine。已统一为 Go 1.26

## COMMANDS

```bash
make all          # fmt → lint → test → build
make build        # 构建 bin/security-exporter
make build-linux  # 交叉编译 Linux amd64
make test         # go test -v ./...
make lint         # go vet ./...
make docker-build # Docker 镜像构建
make docker-run   # Docker 运行（--privileged）
make bpf-generate  # 生成 BPF Go 绑定（需要 Linux/Docker 环境）
make bpf-build     # 完整构建含 BPF（generate + build）
```

## NOTES

- Docker 运行**必须** `--privileged`，因为需要读取 `/proc`、`/etc/shadow` 等系统文件
- `process_info.go` 是最复杂的文件（1347 行），包含 Java 应用版本探测的多层策略（HTTP 探测 → cmdline 解析 → JAR manifest → classpath 扫描 → 容器镜像检测）
- 端口采集直接解析 `/proc/net/tcp`（十六进制），不走 `netstat`/`ss` 命令
- `pkg/logger/logger.go` JSON 格式标记为"待扩展"
