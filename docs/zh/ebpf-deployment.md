# eBPF 部署指南

本指南介绍部署 security-collector-exporter 与真实 BPF 程序（非模拟模式）。eBPF 层使用实际的内核追踪点和 BPF 映射进行生产级安全监控。

## 内核版本要求

### 基本要求 (5.4+)
- Linux 内核版本 5.4 或更高
- BPF (Berkeley Packet Filter) 支持
- 基本的 eBPF 程序加载和执行

### 推荐版本 (5.8+)
- 内核版本 5.8+ 支持 ring buffer
- 更好的性能和稳定性
- 支持更多的 eBPF 功能

### 最佳实践 (5.15+)
- 内核版本 5.15+ 推荐
- 完整的 eBPF 功能支持
- 更好的错误处理和调试功能
- 更稳定的内核 API
## 构建要求

### 开发环境
- **Go 1.26+**: 构建 Go 应用程序的必需依赖
- **clang + llvm**: BPF C 编译和 `go generate` 命令的必需依赖
- **Linux 头文件**: 内核特定的 BPF 功能

### BPF 代码生成

BPF 程序需要使用 `bpf2go` 工具进行代码生成：

```bash
# 使用 Docker（推荐，确保一致性）
make bpf-generate

# 本地构建（不使用 Docker）
# 1. 安装 clang + llvm
sudo apt-get install clang llvm  # Ubuntu/Debian
sudo yum install clang llvm      # RHEL/CentOS

# 2. 生成 BPF Go 绑定
go generate ./internal/bpf/...

# 3. 构建主程序
make build
```

### 交叉编译
- BPF 字节码是与架构无关的
- 在任何有 clang/llvm 的平台上生成 BPF 绑定
- 交叉编译 Go 二进制文件到目标架构
- 示例: `GOOS=linux GOARCH=amd64 make build-linux`

## 权限要求
## 权限要求

### 必需权限
运行 eBPF 程序需要以下权限之一：

#### 1. Root 权限
```bash
sudo ./bin/security-exporter
```

#### 2. 特定能力组合
```bash
# 添加所需能力
setcap cap_bpf,cap_perfmon,cap_net_admin+ep ./bin/security-exporter

# 直接运行
./bin/security-exporter
```

### 权限说明
- `CAP_BPF`: 允许加载和执行 eBPF 程序
- `CAP_PERFMON`: 允许使用性能监控工具
- `CAP_NET_ADMIN`: 允许网络相关的 eBPF 操作

## Docker 运行

### 基础 Docker 配置
```yaml
version: '3.8'
services:
  security-exporter:
    image: security-collector-exporter:latest
    restart: unless-stopped
    ports:
      - "9090:9090"
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

### 非特权模式运行
```yaml
version: '3.8'
services:
  security-exporter:
    image: security-collector-exporter:latest
    restart: unless-stopped
    ports:
      - "9090:9090"
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

## Kubernetes 部署

### DaemonSet 配置
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
        - containerPort: 9090
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

### RBAC 配置
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

## 降级场景

### 内核不支持 eBPF
**现象**: 
- 启动时显示 "eBPF not supported" 或类似错误
- 自动回退到传统模式

**解决方案**:
```bash
# 检查内核版本
uname -r

# 检查 eBPF 支持
ls /sys/kernel/bpf/

# 禁用 eBPF 运行
./bin/security-exporter --ebpf.enabled=false
```

### 权限不足
**现象**:
- "Permission denied" 错误
- 无法加载 eBPF 程序

**解决方案**:
```bash
# 检查权限
getcap ./bin/security-exporter

# 重新设置权限
sudo setcap cap_bpf,cap_perfmon,cap_net_admin+ep ./bin/security-exporter

# 或者使用 root 运行
sudo ./bin/security-exporter
```

### BTF (BPF Type Format) 缺失
**现象**:
- "BTF not found" 错误
- 部分功能受限

**解决方案**:
```bash
# 检查 BTF 支持
bpftool btf dump file /sys/kernel/btf/vmlinux format c

# 安装 BTF 支持工具
sudo apt install linux-tools-generic  # Ubuntu
sudo yum install kernel-tools         # RHEL
```

## CLI Flags 参考

### eBPF 相关参数
```bash
# 启用/禁用 eBPF
./bin/security-exporter --ebpf.enabled=true

# 设置采样率 (1-10000)
./bin/security-exporter --ebpf.sample-rate=100

# 启用详细模式
./bin/security-exporter --ebpf.detailed=true

# 限制每秒事件数
./bin/security-exporter --ebpf.max-events-per-second=1000

# 指定网络接口
./bin/security-exporter --ebpf.interfaces="eth0,eth1"

# 设置缓冲区大小
./bin/security-exporter --ebpf.buffer-size=8192
```

### 完整命令示例
```bash
./bin/security-exporter \
  --ebpf.enabled=true \
  --ebpf.sample-rate=100 \
  --ebpf.detailed=false \
  --ebpf.max-events-per-second=1000 \
  --log.level=info \
  --metrics.port=9090 \
  --metrics.path=/metrics
```

## 故障排查

### 常见错误及解决方案

#### 1. 无法加载 eBPF 程序
```bash
# 错误信息: "failed to load eBPF program: permission denied"

# 检查内核版本
uname -r

# 检查权限
ls -la /sys/kernel/bpf/
getcap ./bin/security-exporter

# 解决方案
sudo setcap cap_bpf+ep ./bin/security-exporter
sudo ./bin/security-exporter
```

#### 2. Ring buffer 错误
```bash
# 错误信息: "ring buffer creation failed"

# 检查内核版本
uname -r

# 如果内核 < 5.8，禁用 ring buffer
./bin/security-exporter --ebpf.ring-buffer=false

# 或升级内核
sudo apt upgrade
```

#### 3. 内存不足
```bash
# 错误信息: "out of memory" 或 "buffer overflow"

# 调整缓冲区大小
./bin/security-exporter --ebpf.buffer-size=16384

# 降低采样率
./bin/security-exporter --ebpf.sample-rate=50

# 检查系统内存
free -h
```

### 调试命令

#### 启用详细日志
```bash
./bin/security-exporter --log.level=debug --ebpf.detailed=true
```

#### 检查 eBPF 状态
```bash
# 查看已加载的 eBPF 程序
bpftool prog list

# 查看 BPF 映射
bpftool map list

# 查看 eBPF 连接
bpftool net
```

#### 监控 eBPF 事件
```bash
# 使用 perf 工具监控
perf record -e sys_enter ./bin/security-exporter

# 查看 tracepoints
trace-cmd record -e sys_enter ./bin/security-exporter
```

### 性能优化建议

#### 1. 调整采样率
- 高性能环境: 100-1000
- 生产环境: 10-100
- 调试环境: 1-10

#### 2. 内存管理
- 监控内存使用: `free -h`
- 调整缓冲区大小: `--ebpf.buffer-size`
- 定期重启服务避免内存泄漏

#### 3. 网络优化
- 限制网络接口: `--ebpf.interfaces`
- 使用批量处理: `--ebpf.batch-size`
- 启用压缩: `--ebpf.compression`

## 版本兼容性

| 内核版本 | 功能支持 | 推荐使用场景 |
|---------|---------|-------------|
| 5.4-5.7 | 基本 eBPF | 生产环境，功能受限 |
| 5.8-5.14 | Ring buffer + 更多功能 | 生产环境，推荐使用 |
| 5.15+ | 完整功能 | 生产环境，最佳性能 |

## 最佳实践

1. **测试环境验证**: 先在测试环境验证 eBPF 功能
2. **逐步部署**: 先少量节点部署，监控性能
3. **监控指标**: 监控 eBPF 相关的 Prometheus 指标
4. **备份配置**: 保存原始配置文件
5. **文档记录**: 记录部署过程中的问题和解决方案

## 联系支持

如果遇到文档中未解决的问题，请：
1. 检查日志文件获取详细错误信息
2. 使用 `--log.level=debug` 获取更多调试信息
3. 联系技术支持并提供以下信息：
   - 内核版本
   - 错误日志
   - 系统配置
   - 部署环境