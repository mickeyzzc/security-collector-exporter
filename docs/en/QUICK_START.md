[中文](../zh/QUICK_START.md) | English

# Quick Start Guide

## Build and Run

### 1. Local Build

```bash
# Clone the project
git clone <repository-url>
cd security-collector-exporter

# Build
go build -o security-exporter ./cmd/security-exporter

# Basic run
./security-exporter

# View version info
./security-exporter --version

# Custom configuration
./security-exporter \
  --web.listen-address=:9102 \
  --web.telemetry-path=/metrics \
  --collector.port-states="LISTEN,ESTABLISHED"
```

### 2. Docker Deployment

#### Using Makefile

```bash
# Build Docker image
make docker-build

# Run Docker container
make docker-run

# Stop container
make docker-stop

# Clean up images
make docker-clean
```

#### Using docker-compose

```bash
# Build and start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Rebuild and start
docker-compose up -d --build
```

#### Manual Docker Commands

```bash
# Build image
docker build -t security-exporter:latest .

# Run container
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

### 3. Verify Installation

```bash
# Check service status
curl http://localhost:9102/metrics

# View specific metrics
curl http://localhost:9102/metrics | grep linux_security_os_version_info

# View all metrics
curl http://localhost:9102/metrics

# View port usage info
curl http://localhost:9102/metrics | grep linux_security_ports_use_info
```

## Configuration Reference

### Basic Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--web.listen-address` | `:9102` | Web server listen address |
| `--web.telemetry-path` | `/metrics` | Metrics exposure path |

### Port State Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--collector.port-states` | `LISTEN` | TCP port states to collect, multiple states separated by commas |

### Collector Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--collector.go-metrics` | `false` | Whether to collect Go runtime metrics (go_* metrics), disabled by default |
| `--collector.services-enabled` | `true` | Whether to collect only enabled services, default true (only collects services with is_enabled=true) |
| `--collector.services-running` | `false` | Whether to collect only running services, default false (no filtering by running status) |

### Log Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--log.level` | `info` | Log level: debug, info, warn, error |
| `--log.format` | `logfmt` | Log format: logfmt, json |

#### Available TCP States

- `LISTEN` - Listening state
- `ESTABLISHED` - Connection established
- `SYN_SENT` - SYN sent
- `SYN_RECV` - SYN received
- `FIN_WAIT1` - Waiting for FIN
- `FIN_WAIT2` - Waiting for FIN
- `TIME_WAIT` - Time wait
- `CLOSE` - Closed
- `CLOSE_WAIT` - Waiting to close
- `LAST_ACK` - Last acknowledgment
- `CLOSING` - Closing

#### Usage Examples

```bash
# Collect LISTEN state only (default)
./security-exporter

# Collect LISTEN and ESTABLISHED states
./security-exporter --collector.port-states="LISTEN,ESTABLISHED"

# Collect all TCP states
./security-exporter --collector.port-states="LISTEN,ESTABLISHED,SYN_SENT,SYN_RECV,FIN_WAIT1,FIN_WAIT2,TIME_WAIT,CLOSE,CLOSE_WAIT,LAST_ACK,CLOSING"

# Enable debug mode
./security-exporter --log.level=debug

# Use JSON log format
./security-exporter --log.level=info --log.format=json

# Enable Go runtime metrics collection
./security-exporter --collector.go-metrics

# Collect all services (including disabled and stopped services)
./security-exporter --collector.services-enabled=false

# Collect only running services
./security-exporter --collector.services-running=true

# Collect only services that are both enabled and running
./security-exporter --collector.services-enabled=true --collector.services-running=true
```

## Prometheus Configuration

### 1. Add Scrape Configuration

Add the following to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'security-collector'
    static_configs:
      - targets: ['localhost:9102']
    scrape_interval: 30s
    metrics_path: /metrics
```

### 2. Restart Prometheus

```bash
# Reload configuration
curl -X POST http://localhost:9090/-/reload

# Or restart the service
systemctl restart prometheus
```

## Basic Query Examples

### System Information Queries

```promql
# Operating system version
linux_security_os_version_info

# System account info (passwd file info)
linux_security_account_info

# Password policy metrics
linux_security_last_password_change
linux_security_password_max_days
linux_security_password_min_days
linux_security_password_warn_days
linux_security_password_inactive
linux_security_account_expire

# SSH configuration
linux_security_sshd_config_info
```

### Security Status Checks

```promql
# Check if SSH root login is disabled
linux_security_sshd_config_info{info_key="PermitRootLogin", info_value="no"}

# Check if SELinux is enabled
linux_security_selinux_config{info_key="SELINUX", info_value="enforcing"}

# Check firewall status (enabled and running)
linux_security_firewall_enabled{firewall_type="firewalld", is_running="true"} == 1

# Check port usage
linux_security_ports_use_info{process="sshd", port="22"}

# View ports by specific protocol
linux_security_ports_use_info{protocol="tcp", state="LISTEN"}

# View port details (including version and application name)
linux_security_ports_use_info{app_name="nginx", version!=""}

# Check password policy
linux_security_login_defs_info{info_key="PASS_MIN_LEN", info_value="num"} >= 10

# View system target info (run level)
linux_security_system_target_info{current_target="multi-user.target"}

# View service information
linux_security_services_info{service_name="sshd", is_running="true"}

# View system patch and package information
linux_security_last_patch_time{package_type!="unknown"}
linux_security_package_count{package_type="dpkg"}
```

## Troubleshooting

### Common Issues

1. **Insufficient Permissions**
   ```bash
   # Ensure running with root privileges
   sudo ./security-exporter
   ```

2. **Port Already in Use**
   ```bash
   # Check port usage
   netstat -tlnp | grep 9102
   
   # Use a different port
   ./security-exporter --web.listen-address=:9103
   ```

3. **Empty Metrics**
   ```bash
   # Check system file permissions
   ls -la /etc/passwd /etc/ssh/sshd_config
   
   # Check logs
   journalctl -u security-exporter
   ```

### Debug Mode

```bash
# Enable verbose logging
./security-exporter --log.level=debug

# View detailed process matching logs
./security-exporter --log.level=debug 2>&1 | grep "getProcessByInode"

# Use JSON format debug logs
./security-exporter --log.level=debug --log.format=json
```

## Next Steps

- See the [Security Checklist](SECURITY_CHECKLIST.md) for detailed security check items
- Configure [Alert Rules](SECURITY_CHECKLIST.md#prometheus-alert-rules) for automated monitoring
- Refer to [Prometheus Query Examples](SECURITY_CHECKLIST.md#additional-query-examples) for in-depth analysis
