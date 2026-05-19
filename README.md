[中文](README.zh.md) | English

# Security Collector Exporter

Linux Security Information Collector Prometheus Exporter, used for monitoring server security status. Collects security metrics including accounts, SSH, firewall, ports, services, patches, processes, and supports real eBPF security event monitoring using 5 actual BPF programs with 14 kernel tracepoints.

## Quick Start

### Build and Run

#### Local Build

```bash
# 1. Generate BPF Go bindings (requires clang/llvm)
go generate ./internal/bpf/...

# 2. Build the application
go build -o security-exporter ./cmd/security-exporter

# 3. Run
./security-exporter --web.listen-address=:9102 --web.telemetry-path=/metrics
```

#### Docker Deployment

```bash
# Build Docker image
make docker-build

# Run Docker container (needs privileged mode to read system files)
make docker-run

# Or use docker-compose
docker-compose up -d
```

#### Systemd Deployment (Recommended for Production)

```bash
# 1. Deploy binary
sudo cp security-exporter /usr/local/bin/

# 2. Create systemd service
sudo cat > /etc/systemd/system/security-exporter.service << 'EOF'
[Unit]
Description=Security Collector Exporter
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/security-exporter --web.listen-address=:9102
Restart=on-failure
RestartSec=5

# Need to read /etc/shadow, /proc, etc. system files
AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE

[Install]
WantedBy=multi-user.target
EOF

# 3. Start service
sudo systemctl daemon-reload
sudo systemctl enable --now security-exporter

# Verify
curl -s localhost:9102/metrics | head
```

### Configuration Parameters

#### Basic Configuration

| Parameter | Default | Description |
|----------|---------|-------------|
| `--web.listen-address` | `:9102` | Web service listening address |
| `--web.telemetry-path` | `/metrics` | Metrics exposure path |
| `--version` | - | Show version info and exit |

#### Port State Configuration

| Parameter | Default | Description |
|----------|---------|-------------|
| `--collector.port-states` | `LISTEN` | TCP port states to collect, multiple states separated by comma |

#### Collector Configuration

| Parameter | Default | Description |
|----------|---------|-------------|
| `--collector.go-metrics` | `false` | Whether to collect Go performance metrics (go_* metrics), disabled by default |
| `--collector.services-enabled` | `true` | Whether to only collect enabled services, default true (only collect is_enabled=true services) |
| `--collector.services-running` | `false` | Whether to only collect running services, default false (don't filter running state) |

#### Log Configuration

| Parameter | Default | Description |
|----------|---------|-------------|
| `--log.level` | `info` | Log level: debug, info, warn, error |
| `--log.format` | `logfmt` | Log format: logfmt, json |

#### eBPF Security Event Monitoring Configuration

| Parameter | Default | Description |
|----------|---------|-------------|
| `--ebpf.enabled` | `false` | Whether to enable eBPF security event monitoring (requires Linux 5.4+, needs privileges) |
| `--ebpf.sample-rate` | `1` | eBPF event sampling rate (1=every event, 10=1 out of 10 events) |
| `--ebpf.detailed` | `false` | Whether to enable detailed mode (Ring Buffer + Top-N tracking, higher resource consumption) |
| `--ebpf.max-events-per-second` | `5000` | Maximum events per second, adaptive downsampling after exceeding this limit |

#### Usage Examples

```bash
# Basic run
./security-exporter

# Custom port states
./security-exporter --collector.port-states="LISTEN,ESTABLISHED"

# Enable debug mode
./security-exporter --log.level=debug

# Use JSON log format
./security-exporter --log.level=info --log.format=json

# Enable Go performance metrics collection
./security-exporter --collector.go-metrics

# Collect all services (including disabled and non-running)
./security-exporter --collector.services-enabled=false

# Only collect running services
./security-exporter --collector.services-running=true

# Only collect both enabled and running services
./security-exporter --collector.services-enabled=true --collector.services-running=true

# Enable eBPF security event monitoring (needs Linux 5.4+ and privileged mode)
./security-exporter --ebpf.enabled=true

# Enable eBPF + detailed mode (Ring Buffer + Top-N, higher resource consumption)
./security-exporter --ebpf.enabled=true --ebpf.detailed=true

# Enable eBPF + custom sampling rate
./security-exporter --ebpf.enabled=true --ebpf.sample-rate=10 --ebpf.max-events-per-second=10000
```

## Project Structure

```
security-collector-exporter/
├── cmd/security-exporter/     # Entry point, HTTP server + Prometheus registration
├── internal/
│   ├── bpf/                 # eBPF BPF C programs + Go bindings
│   │   ├── sources/         # BPF C source files
│   │   ├── bpf2go.go        # go:generate instructions
│   │   └── types.go         # BPF constants Go bindings
│   ├── collector/            # Prometheus collector
│   │   ├── security_collector.go  # Traditional security metrics collection
│   │   └── ebpf_collector.go     # eBPF metrics collection
│   ├── ebpf/                 # eBPF Go integration layer
│   │   ├── manager.go       # Lifecycle management
│   │   ├── aggregator.go    # BPF Map aggregation reader
│   │   ├── spacesaving.go   # Space-Saving Top-N
│   │   ├── sampler.go       # Adaptive sampling
│   │   └── fallback.go      # Graceful degradation
│   └── system/               # Core collection logic (12 files)
│       ├── account_info.go   # Account/shadow
│       ├── network_info.go   # Port/firewall
│       ├── process_info.go   # Process version detection
│       ├── config_info.go    # SSH/SELinux configuration
│       └── ...
├── pkg/
│   ├── config/              # CLI flags + version injection
│   └── logger/              # Log wrapper
├── docs/
│   ├── zh/              # Chinese documentation
│   ├── en/              # English documentation
│   └── README.md        # Documentation navigation
├── Makefile
├── Dockerfile
└── docker-compose.yml
```

## Monitoring Metrics

The collector provides the following security-related metrics:

### Basic System Information
- `linux_security_os_version_info`: Operating system version information
- `linux_security_account_info`: System account information (passwd file information)
- `linux_security_sshd_config_info`: SSH service configuration information

### Password Policy Metrics
- `linux_security_last_password_change`: Last password change time (days)
- `linux_security_password_max_days`: Password maximum validity period (days)
- `linux_security_password_min_days`: Password minimum validity period (days)
- `linux_security_password_warn_days`: Password warning days
- `linux_security_password_inactive`: Password inactive days
- `linux_security_account_expire`: Account expiration time (days)

### Password Policy Check
- `linux_security_login_defs_info`: login.defs configuration information

### System Security Configuration
- `linux_security_selinux_config`: SELinux configuration information
- `linux_security_firewall_enabled`: Firewall status (including firewall type and running state)
  - Supported types: firewalld, ufw, iptables, nftables
- `linux_security_ports_use_info`: System port usage information (including protocol, IP, port, state, process name, executable path, version, application name)
  - Protocols: tcp, tcp6, udp, udp6
  - TCP states: LISTEN, ESTABLISHED, SYN_SENT, SYN_RECV, FIN_WAIT1, FIN_WAIT2, TIME_WAIT, CLOSE, CLOSE_WAIT, LAST_ACK, CLOSING
- `linux_security_hosts_options_info`: hosts.deny and hosts.allow configuration information

### System Service Check
- `linux_security_services_info`: System service information
- `linux_security_system_target_info`: System target information

### System Maintenance
- `linux_security_last_patch_time`: Last patch time
  - Supported package manager types: rpm (RedHat/CentOS), dpkg (Debian/Ubuntu), pacman (Arch Linux)
- `linux_security_package_count`: Installed package count
  - Supported package manager types: rpm (RedHat/CentOS), dpkg (Debian/Ubuntu), pacman (Arch Linux)

### eBPF Security Event Monitoring (requires --ebpf.enabled=true)

Uses real BPF programs loaded into the kernel with actual tracepoint monitoring (5 programs, 14 tracepoints).

#### Metadata
- `security_ebpf_up`: eBPF monitoring status (status label: active/degraded/disabled)
- `security_ebpf_sample_rate`: Current sampling rate

#### Process Metrics (type label: system/user/container/suspicious)
- `security_ebpf_process_exec_total`: Process execution count
- `security_ebpf_process_exit_total`: Process exit count
- `security_ebpf_process_active_count`: Active process count

#### Network Metrics
- `security_ebpf_connect_total`: Network connection total (direction×protocol, cardinality 4)
- `security_ebpf_connect_active`: Current active connection count
- `security_ebpf_connect_error_total`: Connection error count (type label: timeout/refused/reset)

#### File Access (severity×operation, cardinality 6)
- `security_ebpf_file_access_total`: Sensitive file access count

#### Privilege Escalation Detection (type×result, cardinality 6)
- `security_ebpf_privilege_escalation_total`: Privilege escalation attempt count

#### Kernel Modules (action label, cardinality 2)
- `security_ebpf_kernel_module_total`: Kernel module operation count

## Documentation

- [Quick Start Guide](docs/en/QUICK_START.md) - Build, run, and basic configuration guide
- [Security Checklist](docs/en/SECURITY_CHECKLIST.md) - Detailed security check items and PromQL query examples
- [Prometheus Query Examples](docs/en/SECURITY_CHECKLIST.md#prometheus-query-examples) - Query methods for various security metrics
- [Alert Rule Examples](docs/en/SECURITY_CHECKLIST.md#alert-rule-examples) - Alert configuration based on security metrics
- [eBPF Architecture Design](docs/en/ebpf-architecture.md) - eBPF integration architecture design document
- [eBPF Deployment Guide](docs/en/ebpf-deployment.md) - Kernel requirements, deployment, and troubleshooting

## Security Standard Compliance

This collector is designed based on Linux security configuration standards, checking the following key security requirements:

1. **Account Management**: Check account creation, permission configuration
2. **Password Policy**: Verify password complexity, validity period, lockout policy
3. **System Configuration**: Check SELinux, firewall, TCP Wrappers configuration
4. **Service Management**: Identify unnecessary services and accounts
5. **System Maintenance**: Monitor patch update status

## Usage Examples

### Basic Queries

```promql
# Check SSH configuration
linux_security_sshd_config_info{info_key="PermitRootLogin", info_value="no"}

# Check SELinux status
linux_security_selinux_config{info_key="SELINUX", info_value="enforcing"}

# Check firewall status (enabled and running)
linux_security_firewall_enabled{firewall_type="firewalld", is_running="true"} == 1

# Check port usage
linux_security_ports_use_info{process="sshd", port="22"}

# Check password policy
linux_security_login_defs_info{info_key="PASS_MIN_LEN", info_value="num"} >= 10
```

### eBPF Security Event Queries

```promql
# eBPF monitoring status
security_ebpf_up

# Process execution count (by type)
security_ebpf_process_exec_total

# Active process count
security_ebpf_process_active_count

# Network connection statistics
security_ebpf_connect_total

# Network connection errors
security_ebpf_connect_error_total

# Sensitive file access
security_ebpf_file_access_total

# Privilege escalation attempts
security_ebpf_privilege_escalation_total

# Kernel module operations
security_ebpf_kernel_module_total

# Current sampling rate
security_ebpf_sample_rate
```

For more detailed configuration instructions, query examples, and alert rules, please refer to:
- [Quick Start Guide](docs/en/QUICK_START.md) - Detailed configuration and operation instructions
- [Security Checklist](docs/en/SECURITY_CHECKLIST.md) - Complete query examples and alert rules