package ebpf

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
)

// Aggregator 从 BPF percpu_array maps 读取预聚合数据。
// 它不直接暴露 BPF map，而是提供结构化的读取方法。
type Aggregator struct {
	// 进程 maps
	processExecCount  *ebpf.Map // BpfProcessMaps.ExecCategoryCount
	processExitCount  *ebpf.Map // BpfProcessMaps.ExitCategoryCount
	processActive     *ebpf.Map // BpfProcessMaps.ActiveProcessCount

	// 网络 maps
	connectTotal      *ebpf.Map // BpfNetworkMaps.ConnectTotal
	connectActive     *ebpf.Map // BpfNetworkMaps.ConnectActive
	connectErrorTotal *ebpf.Map // BpfNetworkMaps.ConnectErrorTotal

	// 文件 maps
	fileAccessTotal *ebpf.Map // BpfFileMaps.FileAccessTotal

	// 提权 maps
	privilegeTotal *ebpf.Map // BpfPrivilegeMaps.PrivilegeEscalationTotal

	// 内核模块 maps
	moduleLoadTotal *ebpf.Map // BpfKernelMaps.ModuleLoadTotal

	// 增量追踪
	mu         sync.Mutex
	prevValues map[uint32]uint64
}

// BpfMaps 持有所有 BPF map 引用，由 Manager 在加载后注入
type BpfMaps struct {
	ProcessExecCount  *ebpf.Map
	ProcessExitCount  *ebpf.Map
	ProcessActive     *ebpf.Map
	ConnectTotal      *ebpf.Map
	ConnectActive     *ebpf.Map
	ConnectErrorTotal *ebpf.Map
	FileAccessTotal   *ebpf.Map
	PrivilegeTotal    *ebpf.Map
	ModuleLoadTotal   *ebpf.Map
}

// NewAggregator 创建聚合器（map 引用稍后通过 SetMaps 注入）
func NewAggregator() *Aggregator {
	return &Aggregator{}
}

// SetMaps 设置 BPF map 引用，由 Manager 在 BPF 程序加载后调用
func (a *Aggregator) SetMaps(maps *BpfMaps) {
	a.processExecCount = maps.ProcessExecCount
	a.processExitCount = maps.ProcessExitCount
	a.processActive = maps.ProcessActive
	a.connectTotal = maps.ConnectTotal
	a.connectActive = maps.ConnectActive
	a.connectErrorTotal = maps.ConnectErrorTotal
	a.fileAccessTotal = maps.FileAccessTotal
	a.privilegeTotal = maps.PrivilegeTotal
	a.moduleLoadTotal = maps.ModuleLoadTotal
}

// readPercpuUint64 从 percpu_array map 中读取指定 key 的值，
// 将所有 CPU 上的值求和后返回
func readPercpuUint64(m *ebpf.Map, key uint32) (uint64, error) {
	if m == nil {
		return 0, nil
	}

	// percpu_array Lookup 返回 []uint64，长度等于 possible CPUs
	// cilium/ebpf 会自动根据系统 CPU 数量调整 slice
	var values []uint64
	if err := m.Lookup(key, &values); err != nil {
		return 0, fmt.Errorf("lookup percpu key %d: %w", key, err)
	}

	var total uint64
	for _, v := range values {
		total += v
	}
	return total, nil
}

// ProcessStats 进程统计
type ProcessStats struct {
	ExecCount   map[string]uint64 // type → count
	ExitCount   map[string]uint64
	ActiveCount map[string]uint64
}

// NetworkStats 网络统计
type NetworkStats struct {
	ConnectTotal  map[string]uint64 // "direction_protocol" → count
	ConnectActive map[string]uint64
	ErrorCount    map[string]uint64 // "error_type" → count
}

// FileStats 文件访问统计
type FileStats struct {
	AccessCount map[string]uint64 // "severity_operation" → count
}

// PrivilegeStats 提权统计
type PrivilegeStats struct {
	EscalationCount map[string]uint64 // "type_result" → count
}

// KernelStats 内核模块统计
type KernelStats struct {
	ModuleLoadCount map[string]uint64 // "action" → count
}

// ReadProcessStats 读取进程统计
func (a *Aggregator) ReadProcessStats() ProcessStats {
	categories := []string{"system", "user", "container", "suspicious"}
	stats := ProcessStats{
		ExecCount:   make(map[string]uint64),
		ExitCount:   make(map[string]uint64),
		ActiveCount: make(map[string]uint64),
	}
	for i, cat := range categories {
		key := uint32(i)
		v, _ := readPercpuUint64(a.processExecCount, key)
		stats.ExecCount[cat] = v

		v, _ = readPercpuUint64(a.processExitCount, key)
		stats.ExitCount[cat] = v

		v, _ = readPercpuUint64(a.processActive, key)
		stats.ActiveCount[cat] = v
	}
	return stats
}

// ReadNetworkStats 读取网络统计
func (a *Aggregator) ReadNetworkStats() NetworkStats {
	keys := []string{"in_tcp", "in_udp", "out_tcp", "out_udp"}
	stats := NetworkStats{
		ConnectTotal:  make(map[string]uint64),
		ConnectActive: make(map[string]uint64),
	}
	for i, k := range keys {
		key := uint32(i)
		v, _ := readPercpuUint64(a.connectTotal, key)
		stats.ConnectTotal[k] = v

		v, _ = readPercpuUint64(a.connectActive, key)
		stats.ConnectActive[k] = v
	}
	errKeys := []string{"timeout", "refused", "reset"}
	stats.ErrorCount = make(map[string]uint64)
	for i, k := range errKeys {
		v, _ := readPercpuUint64(a.connectErrorTotal, uint32(i))
		stats.ErrorCount[k] = v
	}
	return stats
}

// ReadFileStats 读取文件访问统计
func (a *Aggregator) ReadFileStats() FileStats {
	severities := []string{"critical", "warning", "info"}
	operations := []string{"read", "write"}
	stats := FileStats{AccessCount: make(map[string]uint64)}
	for s, sev := range severities {
		for o, op := range operations {
			key := sev + "_" + op
			idx := uint32(s*2 + o)
			v, _ := readPercpuUint64(a.fileAccessTotal, idx)
			stats.AccessCount[key] = v
		}
	}
	return stats
}

// ReadPrivilegeStats 读取提权统计
func (a *Aggregator) ReadPrivilegeStats() PrivilegeStats {
	types := []string{"setuid", "setgid", "capset"}
	results := []string{"success", "failure"}
	stats := PrivilegeStats{EscalationCount: make(map[string]uint64)}
	for t, tp := range types {
		for r, res := range results {
			key := tp + "_" + res
			idx := uint32(t*2 + r)
			v, _ := readPercpuUint64(a.privilegeTotal, idx)
			stats.EscalationCount[key] = v
		}
	}
	return stats
}

// ReadKernelStats 读取内核模块统计
func (a *Aggregator) ReadKernelStats() KernelStats {
	actions := []string{"load", "load_file"}
	stats := KernelStats{ModuleLoadCount: make(map[string]uint64)}
	for i, act := range actions {
		v, _ := readPercpuUint64(a.moduleLoadTotal, uint32(i))
		stats.ModuleLoadCount[act] = v
	}
	return stats
}

// ReadAndUpdateFromMaps 从所有 COUNTER BPF maps 读取并计算每周期增量，
// 返回本次读取的增量总和，供自适应采样器使用。
// 注意：processActive 和 connectActive 是 GAUGE 类型，不参与增量计算。
func (a *Aggregator) ReadAndUpdateFromMaps() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()

	// 延迟初始化 prevValues
	if a.prevValues == nil {
		a.prevValues = make(map[uint32]uint64)
	}

	// 定义所有 COUNTER map 及其 key 范围（不含 gauge maps）
	type counterMap struct {
		m     *ebpf.Map
		base  uint32 // prevValues key 偏移基数
		count uint32 // key 数量
	}
	counters := []counterMap{
		{a.processExecCount, 0, 4},
		{a.processExitCount, 100, 4},
		{a.connectTotal, 200, 4},
		{a.connectErrorTotal, 300, 3},
		{a.fileAccessTotal, 400, 6},
		{a.privilegeTotal, 500, 6},
		{a.moduleLoadTotal, 600, 2},
	}

	var deltaTotal uint64
	for _, c := range counters {
		for i := uint32(0); i < c.count; i++ {
			cur, err := readPercpuUint64(c.m, i)
			if err != nil {
				continue
			}
			prevKey := c.base + i
			prev := a.prevValues[prevKey]
			delta := cur - prev // 无符号减法：首次 prev=0 时 delta=cur
			a.prevValues[prevKey] = cur
			deltaTotal += delta
		}
	}

	return deltaTotal
}
