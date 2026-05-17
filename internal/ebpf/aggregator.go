package ebpf

// Aggregator 从 BPF maps 读取预聚合数据。
// 它不直接暴露 BPF map，而是提供结构化的读取方法。
type Aggregator struct {
	// bpfMaps 将在后续任务中连接到实际 BPF maps
	// 当前为 placeholder，使用内存中的数组模拟 percpu_array maps
	processExecCount   [4]uint64 // 按 ProcSystem/ProcUser/ProcContainer/ProcSuspicious 索引
	processExitCount   [4]uint64
	processActiveCount [4]uint64
	connectTotal       [4]uint64 // 按 DirIn+ProtoTCP, DirIn+ProtoUDP, DirOut+ProtoTCP, DirOut+ProtoUDP 索引
	connectActive      [4]uint64
	connectErrorCount  [3]uint64 // 按 ErrTimeout/ErrRefused/ErrReset 索引
	fileAccessCount    [6]uint64 // 按 severity×operation 索引
	privilegeCount     [6]uint64 // 按 type×result 索引
	moduleLoadCount    [2]uint64 // 按 ActionLoad/ActionLoadFile 索引
}

// NewAggregator 创建聚合器
func NewAggregator() *Aggregator {
	return &Aggregator{}
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
		stats.ExecCount[cat] = a.processExecCount[i]
		stats.ExitCount[cat] = a.processExitCount[i]
		stats.ActiveCount[cat] = a.processActiveCount[i]
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
		stats.ConnectTotal[k] = a.connectTotal[i]
		stats.ConnectActive[k] = a.connectActive[i]
	}
	errKeys := []string{"timeout", "refused", "reset"}
	stats.ErrorCount = make(map[string]uint64)
	for i, k := range errKeys {
		stats.ErrorCount[k] = a.connectErrorCount[i]
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
			idx := s*2 + o
			stats.AccessCount[key] = a.fileAccessCount[idx]
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
			idx := t*2 + r
			stats.EscalationCount[key] = a.privilegeCount[idx]
		}
	}
	return stats
}

// ReadKernelStats 读取内核模块统计
func (a *Aggregator) ReadKernelStats() KernelStats {
	actions := []string{"load", "load_file"}
	stats := KernelStats{ModuleLoadCount: make(map[string]uint64)}
	for i, act := range actions {
		stats.ModuleLoadCount[act] = a.moduleLoadCount[i]
	}
	return stats
}

// UpdateProcessCount 更新进程计数（模拟 BPF map 读取，后续替换为真实 map 读取）
func (a *Aggregator) UpdateProcessCount(category int, execDelta, exitDelta, activeDelta uint64) {
	if category >= 0 && category < 4 {
		a.processExecCount[category] += execDelta
		a.processExitCount[category] += exitDelta
		a.processActiveCount[category] += activeDelta
	}
}

// UpdateNetworkCount 更新网络计数
func (a *Aggregator) UpdateNetworkCount(directionProto int, totalDelta, activeDelta uint64) {
	if directionProto >= 0 && directionProto < 4 {
		a.connectTotal[directionProto] += totalDelta
		a.connectActive[directionProto] += activeDelta
	}
}

// UpdateNetworkError 更新网络错误计数
func (a *Aggregator) UpdateNetworkError(errorType int, delta uint64) {
	if errorType >= 0 && errorType < 3 {
		a.connectErrorCount[errorType] += delta
	}
}

// UpdateFileAccess 更新文件访问计数
func (a *Aggregator) UpdateFileAccess(index int, delta uint64) {
	if index >= 0 && index < 6 {
		a.fileAccessCount[index] += delta
	}
}

// UpdatePrivilege 更新提权计数
func (a *Aggregator) UpdatePrivilege(index int, delta uint64) {
	if index >= 0 && index < 6 {
		a.privilegeCount[index] += delta
	}
}

// UpdateModuleLoad 更新内核模块加载计数
func (a *Aggregator) UpdateModuleLoad(action int, delta uint64) {
	if action >= 0 && action < 2 {
		a.moduleLoadCount[action] += delta
	}
}

// Reset 清零所有计数器
func (a *Aggregator) Reset() {
	a.processExecCount = [4]uint64{}
	a.processExitCount = [4]uint64{}
	a.processActiveCount = [4]uint64{}
	a.connectTotal = [4]uint64{}
	a.connectActive = [4]uint64{}
	a.connectErrorCount = [3]uint64{}
	a.fileAccessCount = [6]uint64{}
	a.privilegeCount = [6]uint64{}
	a.moduleLoadCount = [2]uint64{}
}
