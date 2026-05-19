[中文](../zh/ebpf-deployment.md) | English

# eBPF Deployment Guide

This guide covers deploying security-collector-exporter with real BPF programs (not simulation mode). The eBPF layer uses actual kernel tracepoints and BPF maps for production security monitoring.

## Kernel Version Requirements

### Minimum Requirements (5.4+)
- Linux kernel version 5.4 or higher
- BPF (Berkeley Packet Filter) support
- Basic eBPF program loading and execution

### Recommended Version (5.8+)
- Kernel version 5.8+ supports ring buffer
- Better performance and stability
- Support for more eBPF features

### Best Practice (5.15+)
- Kernel version 5.15+ recommended
- Complete eBPF feature support
- Better error handling and debugging capabilities
- More stable kernel APIs

## Permission Requirements

### Required Permissions
Running eBPF programs requires one of the following permission levels:

#### 1. Root Privileges
```bash
sudo ./bin/security-exporter
```

#### 2. Specific Capability Combination
```bash
# Add required capabilities
setcap cap_bpf,cap_perfmon,cap_net_admin+ep ./bin/security-exporter

# Run directly
./bin/security-exporter
```

### Permission Details
- `CAP_BPF`: Allows loading and executing eBPF programs
- `CAP_PERFMON`: Allows using performance monitoring tools
- `CAP_NET_ADMIN`: Allows network-related eBPF operations

## Build Requirements

### Development Environment
- **Go 1.26+**: Required for building the Go application
- **clang + llvm**: Required for BPF C compilation and `go generate` commands
- **Linux headers**: For kernel-specific BPF features

### BPF Code Generation

The BPF programs require code generation using `bpf2go` tool:

```bash
# Using Docker (recommended for consistency)
make bpf-generate

# Local build without Docker
# 1. Install clang + llvm
sudo apt-get install clang llvm  # Ubuntu/Debian
sudo yum install clang llvm      # RHEL/CentOS

# 2. Generate BPF Go bindings
go generate ./internal/bpf/...

# 3. Build the main application
make build
```

### Cross-compilation
- BPF bytecode is architecture-independent
- Generate BPF bindings on any platform with clang/llvm
- Cross-compile Go binary for target architecture
- Example: `GOOS=linux GOARCH=amd64 make build-linux`

## Runtime Requirements

### Kernel Version Requirements
- **Minimum**: Linux 5.4+ (basic BPF support)
- **Recommended**: Linux 5.8+ (ring buffer support)
- **Best**: Linux 5.15+ (complete eBPF feature set)

### BTF Support
- Modern kernels include BTF (BPF Type Format) automatically
- Required for detailed BPF program debugging
- Install kernel headers if missing:
```bash
sudo apt install linux-headers-$(uname -r)  # Ubuntu
sudo yum install kernel-devel               # RHEL
```

### Permissions
Real BPF programs require kernel privileges:
```bash
# Option 1: Root privileges (recommended)
sudo ./security-exporter --ebpf.enabled=true

# Option 2: Specific capabilities
sudo setcap cap_bpf,cap_perfmon,cap_net_admin+ep ./security-exporter
./security-exporter --ebpf.enabled=true
```

### Basic Docker Configuration
```yaml
version: '3.8'
services:
  security-exporter:
    image: security-collector-exporter:latest
    restart: unless-stopped
    ports:
      - "9102:9102"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /etc:/host/etc:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    privileged: true
    command:
      - --ebpf.enabled=true
      - --ebpf.sample-rate=100
      - --log.level=info
```

### Non-Privileged Mode
```yaml
version: '3.8'
services:
  security-exporter:
    image: security-collector-exporter:latest
    restart: unless-stopped
    ports:
      - "9102:9102"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /etc:/host/etc:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    cap_add:
      - BPF
      - PERFMON
      - NET_ADMIN
    command:
      - --ebpf.enabled=true
      - --ebpf.sample-rate=100
      - --log.level=info
```

## Kubernetes Deployment

### DaemonSet Configuration
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: security-exporter
  namespace: security
spec:
  selector:
    matchLabels:
      app: security-exporter
  template:
    metadata:
      labels:
        app: security-exporter
    spec:
      containers:
      - name: security-exporter
        image: security-collector-exporter:latest
        ports:
        - containerPort: 9102
          name: metrics
          protocol: TCP
        securityContext:
          privileged: true
        volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: sys
          mountPath: /host/sys
          readOnly: true
        - name: etc
          mountPath: /host/etc
          readOnly: true
        - name: docker-sock
          mountPath: /var/run/docker.sock
          readOnly: true
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        command:
        - --ebpf.enabled=true
        - --ebpf.sample-rate=100
        - --ebpf.detailed=false
        - --log.level=info
        - --node.name=$(NODE_NAME)
      volumes:
      - name: proc
        hostPath:
          path: /proc
      - name: sys
        hostPath:
          path: /sys
      - name: etc
        hostPath:
          path: /etc
      - name: docker-sock
        hostPath:
          path: /var/run/docker.sock
      tolerations:
      - operator: Exists
        effect: NoSchedule
      - operator: Exists
        effect: NoExecute
```

### RBAC Configuration
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: security-exporter
  namespace: security

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: security-exporter
rules:
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list", "watch"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: security-exporter
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: security-exporter
subjects:
- kind: ServiceAccount
  name: security-exporter
  namespace: security
```

## Degradation Scenarios

### Kernel Does Not Support eBPF
**Symptoms**:
- "eBPF not supported" or similar error at startup
- Automatic fallback to traditional mode

**Solution**:
```bash
# Check kernel version
uname -r

# Check eBPF support
ls /sys/kernel/bpf/

# Run with eBPF disabled
./bin/security-exporter --ebpf.enabled=false
```

### Insufficient Permissions
**Symptoms**:
- "Permission denied" error
- Unable to load eBPF programs

**Solution**:
```bash
# Check permissions
getcap ./bin/security-exporter

# Re-set permissions
sudo setcap cap_bpf,cap_perfmon,cap_net_admin+ep ./bin/security-exporter

# Or run as root
sudo ./bin/security-exporter
```

### Missing BTF (BPF Type Format)
**Symptoms**:
- "BTF not found" error
- Some features limited

**Solution**:
```bash
# Check BTF support
bpftool btf dump file /sys/kernel/btf/vmlinux format c

# Install BTF support tools
sudo apt install linux-tools-generic  # Ubuntu
sudo yum install kernel-tools         # RHEL
```

## CLI Flags Reference

### eBPF-Related Parameters
```bash
# Enable/disable eBPF
./bin/security-exporter --ebpf.enabled=true

# Set sample rate (1-10000)
./bin/security-exporter --ebpf.sample-rate=100

# Enable detailed mode
./bin/security-exporter --ebpf.detailed=true

# Limit events per second
./bin/security-exporter --ebpf.max-events-per-second=1000

# Specify network interfaces
./bin/security-exporter --ebpf.interfaces="eth0,eth1"

# Set buffer size
./bin/security-exporter --ebpf.buffer-size=8192
```

### Full Command Example
```bash
./bin/security-exporter \
  --ebpf.enabled=true \
  --ebpf.sample-rate=100 \
  --ebpf.detailed=false \
  --ebpf.max-events-per-second=1000 \
  --log.level=info \
  --web.listen-address=:9102 \
  --web.telemetry-path=/metrics
```

## Troubleshooting

### Common Errors and Solutions

#### 1. Unable to Load eBPF Program
```bash
# Error: "failed to load eBPF program: permission denied"

# Check kernel version
uname -r

# Check permissions
ls -la /sys/kernel/bpf/
getcap ./bin/security-exporter

# Solutions
sudo setcap cap_bpf+ep ./bin/security-exporter
sudo ./bin/security-exporter
```

#### 2. Ring Buffer Error
```bash
# Error: "ring buffer creation failed"

# Check kernel version
uname -r

# If kernel < 5.8, disable ring buffer
./bin/security-exporter --ebpf.ring-buffer=false

# Or upgrade kernel
sudo apt upgrade
```

#### 3. Out of Memory
```bash
# Error: "out of memory" or "buffer overflow"

# Adjust buffer size
./bin/security-exporter --ebpf.buffer-size=16384

# Reduce sample rate
./bin/security-exporter --ebpf.sample-rate=50

# Check system memory
free -h
```

### Debug Commands

#### Enable Verbose Logging
```bash
./bin/security-exporter --log.level=debug --ebpf.detailed=true
```

#### Check eBPF Status
```bash
# View loaded eBPF programs
bpftool prog list

# View BPF maps
bpftool map list

# View eBPF connections
bpftool net
```

#### Monitor eBPF Events
```bash
# Monitor using perf tool
perf record -e sys_enter ./bin/security-exporter

# View tracepoints
trace-cmd record -e sys_enter ./bin/security-exporter
```

### Performance Tuning Recommendations

#### 1. Adjust Sample Rate
- High-performance environments: 100-1000
- Production environments: 10-100
- Debug environments: 1-10

#### 2. Memory Management
- Monitor memory usage: `free -h`
- Adjust buffer size: `--ebpf.buffer-size`
- Periodically restart the service to avoid memory leaks

#### 3. Network Optimization
- Restrict network interfaces: `--ebpf.interfaces`
- Use batch processing: `--ebpf.batch-size`
- Enable compression: `--ebpf.compression`

## Version Compatibility

| Kernel Version | Feature Support | Recommended Use Case |
|---------------|----------------|---------------------|
| 5.4-5.7 | Basic eBPF | Production, limited features |
| 5.8-5.14 | Ring buffer + more features | Production, recommended |
| 5.15+ | Full features | Production, best performance |

## Best Practices

1. **Test Environment Validation**: Validate eBPF features in a test environment first
2. **Gradual Deployment**: Deploy to a small number of nodes first, monitor performance
3. **Monitor Metrics**: Monitor eBPF-related Prometheus metrics
4. **Backup Configuration**: Save original configuration files
5. **Document Everything**: Record issues and solutions encountered during deployment

## Contact Support

If you encounter issues not resolved by this documentation:
1. Check log files for detailed error information
2. Use `--log.level=debug` for more debugging information
3. Contact technical support with the following information:
   - Kernel version
   - Error logs
   - System configuration
   - Deployment environment
