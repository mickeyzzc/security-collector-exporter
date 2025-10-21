# 快速开始指南

## 构建和运行

### 1. 本地构建

```bash
# 克隆项目
git clone <repository-url>
cd Security-Collector

# 构建
go build -o security-exporter ./cmd/security-exporter

# 基本运行
./security-exporter

# 查看版本信息
./security-exporter --version

# 自定义配置
./security-exporter \
  --web.listen-address=:9102 \
  --web.telemetry-path=/metrics \
  --collector.port-states="LISTEN,ESTABLISHED"
```

### 2. Docker 部署

#### 使用 Makefile

```bash
# 构建 Docker 镜像
make docker-build

# 运行 Docker 容器
make docker-run

# 停止容器
make docker-stop

# 清理镜像
make docker-clean
```

#### 使用 docker-compose

```bash
# 构建并启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down

# 重新构建并启动
docker-compose up -d --build
```

#### 手动 Docker 命令

```bash
# 构建镜像
docker build -t security-exporter:latest .

# 运行容器
docker run -d \
  --name security-exporter \
  --privileged \
  -p 9102:9102 \
  -v /etc/passwd:/etc/passwd:ro \
  -v /etc/group:/etc/group:ro \
  -v /proc:/proc:ro \
  -v /sys:/sys:ro \
  security-exporter:latest
```

### 3. 验证运行

```bash
# 检查服务状态
curl http://localhost:9102/metrics

# 查看特定指标
curl http://localhost:9102/metrics | grep linux_security_os_version_info
```

## 配置参数详解

### 基本配置

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--web.listen-address` | `:9102` | Web服务监听地址 |
| `--web.telemetry-path` | `/metrics` | Metrics暴露路径 |

### 端口状态配置

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--collector.port-states` | `LISTEN` | 要采集的TCP端口状态，多个状态用逗号分隔 |

### 日志配置

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--log.level` | `info` | 日志级别：debug, info, warn, error |
| `--log.format` | `logfmt` | 日志格式：logfmt, json |

#### 可用的TCP状态

- `LISTEN` - 监听状态
- `ESTABLISHED` - 已建立连接
- `SYN_SENT` - 发送SYN
- `SYN_RECV` - 接收SYN
- `FIN_WAIT1` - 等待FIN
- `FIN_WAIT2` - 等待FIN
- `TIME_WAIT` - 时间等待
- `CLOSE` - 关闭
- `CLOSE_WAIT` - 等待关闭
- `LAST_ACK` - 最后确认
- `CLOSING` - 正在关闭

#### 使用示例

```bash
# 只采集LISTEN状态（默认）
./security-exporter

# 采集LISTEN和ESTABLISHED状态
./security-exporter --collector.port-states="LISTEN,ESTABLISHED"

# 采集所有TCP状态
./security-exporter --collector.port-states="LISTEN,ESTABLISHED,SYN_SENT,SYN_RECV,FIN_WAIT1,FIN_WAIT2,TIME_WAIT,CLOSE,CLOSE_WAIT,LAST_ACK,CLOSING"

# 开启调试模式
./security-exporter --log.level=debug

# 使用JSON日志格式
./security-exporter --log.level=info --log.format=json
```

## Prometheus配置

### 1. 添加抓取配置

在 `prometheus.yml` 中添加：

```yaml
scrape_configs:
  - job_name: 'security-collector'
    static_configs:
      - targets: ['localhost:9102']
    scrape_interval: 30s
    metrics_path: /metrics
```

### 2. 重启Prometheus

```bash
# 重新加载配置
curl -X POST http://localhost:9090/-/reload

# 或重启服务
systemctl restart prometheus
```

## 基本查询示例

### 系统信息查询

```promql
# 操作系统版本
linux_security_os_version_info

# 系统账户信息（passwd文件信息）
linux_security_account_info

# 密码策略指标
linux_security_last_password_change
linux_security_password_max_days
linux_security_password_min_days
linux_security_password_warn_days
linux_security_password_inactive
linux_security_account_expire

# SSH配置
linux_security_sshd_config_info
```

### 安全状态检查

```promql
# 检查SSH root登录是否禁用
linux_security_sshd_config_info{info_key="PermitRootLogin", info_value="no"}

# 检查SELinux是否启用
linux_security_selinux_config{info_key="SELINUX", info_value="enforcing"}

# 检查防火墙状态（已启用且正在运行）
linux_security_firewall_enabled{firewall_type="firewalld", is_running="true"} == 1

# 检查端口使用情况
linux_security_ports_use_info{process="sshd", port="22"}

# 检查密码策略
linux_security_login_defs_info{info_key="PASS_MIN_LEN", info_value="num"} >= 10
```

## 故障排除

### 常见问题

1. **权限不足**
   ```bash
   # 确保以root权限运行
   sudo ./security-exporter
   ```

2. **端口被占用**
   ```bash
   # 检查端口使用情况
   netstat -tlnp | grep 9102
   
   # 使用其他端口
   ./security-exporter --web.listen-address=:9103
   ```

3. **指标为空**
   ```bash
   # 检查系统文件权限
   ls -la /etc/passwd /etc/ssh/sshd_config
   
   # 检查日志
   journalctl -u security-exporter
   ```

### 调试模式

```bash
# 启用详细日志
./security-exporter --log.level=debug

# 查看详细的进程匹配日志
./security-exporter --log.level=debug 2>&1 | grep "getProcessByInode"

# 使用JSON格式的调试日志
./security-exporter --log.level=debug --log.format=json
```

## 下一步

- 查看 [安全标准检查清单](SECURITY_CHECKLIST.md) 了解详细的安全检查项目
- 配置 [告警规则](SECURITY_CHECKLIST.md#告警规则示例) 实现自动化监控
- 参考 [Prometheus查询示例](SECURITY_CHECKLIST.md#prometheus查询示例) 进行深入分析
