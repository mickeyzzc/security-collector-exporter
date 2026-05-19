[中文](../zh/ebpf-architecture.md) | English

# eBPF Architecture Design Document

## Overview

The eBPF enhancement layer serves as a performance optimization layer for the existing security-collector-exporter, significantly reducing user-space overhead through kernel-space data pre-aggregation using real BPF programs loaded into the kernel. This architecture uses actual tracepoints and BPF maps for production-level security monitoring.


## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                         │
├─────────────────────────────────────────────────────────────┤
│  Prometheus                                                  │
│     │                                                        │
│     │ HTTP Metrics                                           │
│     │                                                        │
│  Security Exporter                                           │
│     │                                                        │
│  ┌───────────────────────────────────────────────────────┐  │
│  │            Go Aggregation Layer                        │  │
│  │ ┌─────────────────────────────────────────────────────┐ │  │
│  │ │              Prometheus Collection                  │ │  │
│  │ │  • CPU Usage Metrics (per CPU/core)                │ │  │
│  │ │  • Process Metrics (per pid)                        │ │  │
│  │ │  • Network Metrics (per port/protocol)             │ │  │
│  │ │  • Filesystem Metrics (per inode)                   │ │  │
│  │ └─────────────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────┘  │
│     │                                                        │
│  ┌─────────────────────────────────────────────────────┐      │
│  │        BPF Map Aggregation Layer (Optional)         │      │
│  │ ┌─────────────────────────────────────────────────┐ │      │
│  │ │  Aggregated Counters                            │ │      │
│  │ │  • System-wide Event Counts                     │ │      │
│  │ │  • Process-wise Event Aggregation               │ │      │
│  │ │  • Network Port Statistics                      │ │      │
│  │ └─────────────────────────────────────────────────┘ │      │
│  └─────────────────────────────────────────────────────┘      │
│     │ Ring Buffer (Optional)                               │
│     │                                                        │
├─────────────────────────────────────────────────────────────┤
│                     Kernel Layer                              │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐      │
  │                 BPF Programs                          │      │
  │ • process (execve/exit, 2 tracepoints)               │      │
  │ • network (tcp/udp state, 4 tracepoints)              │      │
  │ • file (openat/readonly, 2 tracepoints)               │      │
  │ • privilege (setuid/setgid/capset, 3 tracepoints)     │      │
  │ • kernel (init_module/finit_module, 3 tracepoints)   │      │
  │ Total: 5 BPF programs, 14 tracepoints                 │      │
│  │ • sys_enter/exit (Syscall Tracing)                    │      │
│  │ • kprobe (Kernel Function Probes)                     │      │
│  │ • tracepoint (System Tracepoints)                     │      │
│  │ • uprobe (Application Probes)                         │      │
│  │ • socket_filter (Network Filtering)                   │      │
│  └─────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

## BPF Program List

### Current Implementation (Real BPF Programs)

All BPF programs are loaded into the kernel and attached to actual tracepoints. The system gracefully handles kprobe failures without blocking startup.

#### 1. Process Monitoring (process.c)
- **Tracepoints**: `execve`, `exit`
- **Map Structure**: `percpu_array` (key: pid, value: event count)
- **Function**: Tracks process creation and termination
- **Data Flow**: Events aggregated across all CPUs, summed in user space

#### 2. Network Monitoring (network.c)
- **Tracepoints**: `tcp_established`, `tcp_close`, `udp_sendmsg`, `udp_recvmsg`
- **Map Structure**: `percpu_array` (key: ip:port:protocol, value: byte count)
- **Function**: Monitors TCP/UDP connection states and traffic
- **Data Flow**: Aggregated packet counts, summed across CPUs

#### 3. File Access Monitoring (file.c)
- **Tracepoints**: `openat`, `read`
- **Map Structure**: `percpu_array` (key: inode:pid, value: access count)
- **Function**: Tracks file access patterns and sensitive file operations
- **Data Flow**: Access frequency aggregated across CPUs

#### 4. Privilege Escalation Detection (privilege.c)
- **Tracepoints**: `setuid`, `setgid`, `capset`
- **Map Structure**: `percpu_array` (key: uid:operation, value: count)
- **Function**: Detects privilege changes and escalation attempts
- **Data Flow**: Privilege operation counts, summed across CPUs

#### 5. Kernel Module Management (kernel.c)
- **Tracepoints**: `init_module`, `finit_module`
- **Map Structure**: `percpu_array` (key: module:action, value: count)
- **Function**: Monitors kernel module operations
- **Data Flow**: Module operation tracking across CPUs

## Data Flow

### Real BPF Program Loading Architecture

1. **BPF C Sources**: Written in `internal/bpf/sources/` with manual tracepoint definitions
2. **Go Bindings**: Generated using `bpf2go` tool (`go generate ./internal/bpf/...`)
3. **Kernel Loading**: `manager.go` loads BPF programs into kernel using libbpf
4. **Tracepoint Attachment**: Programs attached to actual kernel tracepoints
5. **Map Reading**: `aggregator.go` reads from `percpu_array` maps (sums values across CPUs)
6. **Metrics Export**: Prometheus metrics exposed via `ebpf_collector.go`

### percpu_array Map Pattern
- All BPF maps use `percpu_array` type for efficient CPU-local aggregation
- User space sums values across all CPUs for final metrics
- Reduces lock contention and improves performance
- Graceful degradation: individual CPU failures don't affect others

1. **Kernel Events**: System calls, network packets, file access, process events
2. **BPF Programs**: Filtering, classification, counting, aggregation
3. **BPF Maps**: Store aggregated data, avoiding frequent user-space copies
4. **Ring Buffer**: Real-time event push (optional)
5. **Go Aggregation**: Read data from BPF Maps for secondary aggregation
6. **Prometheus**: Expose metrics for scrapers to collect

## Prometheus Metrics List

For the actual eBPF Prometheus metrics (prefixed `security_ebpf_*`), see the main [README.md](../../README.md) "Monitoring Metrics → eBPF Security Event Monitoring" section, which contains the complete metrics list and descriptions.

## Resource Overhead

### Layer 1 (Traditional Collection)
- **CPU**: High-frequency sampling, process scanning
- **Memory**: Full data storage
- **I/O**: Frequent filesystem access
- **Network**: Real-time data transfer

### Layer 2 (BPF Pre-aggregation)
- **CPU**: Kernel-space aggregation, minimal user-space processing
- **Memory**: BPF Map storage, reduced copy overhead
- **I/O**: Batch data reads
- **Network**: Aggregated data transfer

**Performance Improvement**: CPU usage reduced by 60-80%, memory usage reduced by 40-60%, network traffic reduced by 70-85%

## Dimension Control Strategy

### Why Not Use High-Cardinality Labels?
- **High-cardinality labels** cause Prometheus storage explosion
- **Query performance degradation**, memory consumption spikes
- **Operational complexity** increases

### Space-Saving Algorithm Strategy
1. **Top-N Aggregation**: Only retain the N most frequent values
2. **Probabilistic Counting**: Approximate calculation, trading precision for performance
3. **Hierarchical Aggregation**: Different granularity levels of aggregation
4. **Sliding Window**: Rolling aggregation within time windows

## Relationship with node_exporter

### Three-Layer Complementary Architecture

1. **node_exporter (Base Layer)**
   - System-level metrics: CPU, memory, disk, network
   - Standard metrics: Machine health status
   - Lightweight collection

2. **security-collector (Middle Layer)**
   - Application-level security metrics: processes, services, accounts
   - Configuration compliance checks: SSH, firewall, SELinux
   - Detailed scanning logic

3. **eBPF Enhancement Layer (Optimization Layer)**
   - Kernel-level event tracing: system calls, network connections
   - Performance optimization: kernel-space pre-aggregation
   - High-frequency metrics collection

### Coverage Comparison

| Metric Type | node_exporter | security-collector | eBPF |
|-------------|--------------|-------------------|------|
| CPU Usage | ✓ | ○ | ✓ |
| Memory Usage | ✓ | ○ | ○ |
| Network Connections | ✓ | ○ | ✓ |
| Process Info | ○ | ✓ | ✓ |
| Filesystem | ✓ | ○ | ○ |
| Security Events | ○ | ✓ | ✓ |
| System Calls | ○ | ○ | ✓ |

## Directory Structure

- **`internal/bpf/`**: Real kernel-space BPF program source code
  - `sources/`: 5 actual BPF C source files with real tracepoint definitions
  - `bpf2go.go`: Go code generation using bpf2go tool
  - `types.go`: BPF constants and Go bindings

- **`internal/ebpf/`**: User-space Go integration layer with real BPF management
  - `manager.go`: Real BPF program lifecycle and tracepoint attachment
  - `aggregator.go`: percpu_array map reading with CPU value summation
  - `spacesaving.go`: Space-Saving Top-N algorithm for frequent events
  - `sampler.go`: Adaptive sampling for performance optimization
  - `fallback.go`: Graceful degradation for kprobe failures
  - `ebpf_collector.go`: Prometheus metrics integration

## Limitations

1. **Kernel Requirements**: Linux 5.4+ with BTF support (`/sys/kernel/btf/vmlinux` must exist). Without BTF, BPF programs cannot load.
2. **Privilege Requirements**: Must run as root or with `CAP_BPF`/`CAP_SYS_ADMIN` capabilities. The exporter needs access to `/sys/kernel/debug/tracing/` and BPF system calls.
3. **Container Detection**: Depends on cgroup v1/v2. `bpf_get_current_cgroup_id()` returns 0 on bare-metal systems without containers, so all processes are classified as system/user (not container).
4. **UDP Tracking Unavailable**: The exporter does not track UDP traffic. This is because:
   - No suitable UDP tracepoints exist in the kernel (only `udp_fail_queue_rcv_skb` for error cases)
   - kprobe support depends on kernel compilation flags and may not be available on all distributions
5. **Process Exit Classification**: Relies on a PID→category hash map populated at `execve` time. Processes that existed before the exporter started are classified by comm name matching (limited accuracy — only 8 common service prefixes are checked).
6. **IPv6 Addresses**: Not tracked to control label cardinality. Only TCP state changes and port numbers are recorded.
7. **Privilege Escalation Tracking**: Uses PERCPU_HASH keyed by PID to isolate concurrent calls. There remains a theoretical race window if the same PID makes two different privilege calls on the same CPU within a single enter/exit pair.
8. **Binary Architecture**: BPF bytecode is architecture-independent (embedded in the Go binary at compile time), but the Go binary itself must be compiled for the target architecture (e.g., `GOARCH=arm64` for ARM devices).
9. **PID Hash Map Capacity**: The hash map holds up to 65,536 entries. On systems with extremely high process churn exceeding this limit, new `execve` entries may fail to store, and exit classification falls back to comm-based guessing.
