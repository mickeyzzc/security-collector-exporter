package ebpf

import (
	"testing"
)

func TestNewAggregator(t *testing.T) {
	a := NewAggregator()
	if a == nil {
		t.Fatal("NewAggregator() 返回 nil")
	}
}

func TestReadProcessStats_Initial(t *testing.T) {
	a := NewAggregator()
	stats := a.ReadProcessStats()

	expectedCategories := []string{"system", "user", "container", "suspicious"}
	for _, cat := range expectedCategories {
		if _, ok := stats.ExecCount[cat]; !ok {
			t.Errorf("ExecCount 缺少 key: %s", cat)
		}
		if _, ok := stats.ExitCount[cat]; !ok {
			t.Errorf("ExitCount 缺少 key: %s", cat)
		}
		if _, ok := stats.ActiveCount[cat]; !ok {
			t.Errorf("ActiveCount 缺少 key: %s", cat)
		}
		if stats.ExecCount[cat] != 0 {
			t.Errorf("初始 ExecCount[%s] 应为 0, 实际: %d", cat, stats.ExecCount[cat])
		}
	}
}

func TestUpdateProcessCount(t *testing.T) {
	a := NewAggregator()

	// 更新 system 类别 (category=0)
	a.UpdateProcessCount(0, 10, 2, 8)
	stats := a.ReadProcessStats()

	if stats.ExecCount["system"] != 10 {
		t.Errorf("ExecCount[system] 应为 10, 实际: %d", stats.ExecCount["system"])
	}
	if stats.ExitCount["system"] != 2 {
		t.Errorf("ExitCount[system] 应为 2, 实际: %d", stats.ExitCount["system"])
	}
	if stats.ActiveCount["system"] != 8 {
		t.Errorf("ActiveCount[system] 应为 8, 实际: %d", stats.ActiveCount["system"])
	}

	// 更新 suspicious 类别 (category=3)
	a.UpdateProcessCount(3, 5, 1, 4)
	stats = a.ReadProcessStats()

	if stats.ExecCount["suspicious"] != 5 {
		t.Errorf("ExecCount[suspicious] 应为 5, 实际: %d", stats.ExecCount["suspicious"])
	}

	// 越界 category 应被忽略
	a.UpdateProcessCount(4, 100, 100, 100)
	a.UpdateProcessCount(-1, 100, 100, 100)
	stats = a.ReadProcessStats()
	for _, cat := range []string{"system", "user", "container", "suspicious"} {
		if stats.ExecCount[cat] > 15 {
			t.Errorf("越界 UpdateProcessCount 不应影响数据, ExecCount[%s]=%d", cat, stats.ExecCount[cat])
		}
	}
}

func TestUpdateProcessCount_Accumulative(t *testing.T) {
	a := NewAggregator()

	a.UpdateProcessCount(1, 5, 0, 5)
	a.UpdateProcessCount(1, 3, 1, 2)
	stats := a.ReadProcessStats()

	if stats.ExecCount["user"] != 8 {
		t.Errorf("累积 ExecCount[user] 应为 8, 实际: %d", stats.ExecCount["user"])
	}
	if stats.ExitCount["user"] != 1 {
		t.Errorf("累积 ExitCount[user] 应为 1, 实际: %d", stats.ExitCount["user"])
	}
}

func TestReadNetworkStats_Initial(t *testing.T) {
	a := NewAggregator()
	stats := a.ReadNetworkStats()

	expectedKeys := []string{"in_tcp", "in_udp", "out_tcp", "out_udp"}
	for _, k := range expectedKeys {
		if _, ok := stats.ConnectTotal[k]; !ok {
			t.Errorf("ConnectTotal 缺少 key: %s", k)
		}
		if _, ok := stats.ConnectActive[k]; !ok {
			t.Errorf("ConnectActive 缺少 key: %s", k)
		}
		if stats.ConnectTotal[k] != 0 {
			t.Errorf("初始 ConnectTotal[%s] 应为 0, 实际: %d", k, stats.ConnectTotal[k])
		}
	}

	errKeys := []string{"timeout", "refused", "reset"}
	for _, k := range errKeys {
		if _, ok := stats.ErrorCount[k]; !ok {
			t.Errorf("ErrorCount 缺少 key: %s", k)
		}
	}
}

func TestUpdateNetworkCount(t *testing.T) {
	a := NewAggregator()

	// in_tcp = index 0
	a.UpdateNetworkCount(0, 100, 50)
	stats := a.ReadNetworkStats()

	if stats.ConnectTotal["in_tcp"] != 100 {
		t.Errorf("ConnectTotal[in_tcp] 应为 100, 实际: %d", stats.ConnectTotal["in_tcp"])
	}
	if stats.ConnectActive["in_tcp"] != 50 {
		t.Errorf("ConnectActive[in_tcp] 应为 50, 实际: %d", stats.ConnectActive["in_tcp"])
	}

	// 越界
	a.UpdateNetworkCount(4, 999, 999)
	stats = a.ReadNetworkStats()
	if stats.ConnectTotal["in_tcp"] != 100 {
		t.Errorf("越界 UpdateNetworkCount 不应影响数据")
	}
}

func TestUpdateNetworkError(t *testing.T) {
	a := NewAggregator()

	a.UpdateNetworkError(0, 10) // timeout
	a.UpdateNetworkError(1, 5)  // refused
	a.UpdateNetworkError(2, 3)  // reset
	stats := a.ReadNetworkStats()

	if stats.ErrorCount["timeout"] != 10 {
		t.Errorf("ErrorCount[timeout] 应为 10, 实际: %d", stats.ErrorCount["timeout"])
	}
	if stats.ErrorCount["refused"] != 5 {
		t.Errorf("ErrorCount[refused] 应为 5, 实际: %d", stats.ErrorCount["refused"])
	}
	if stats.ErrorCount["reset"] != 3 {
		t.Errorf("ErrorCount[reset] 应为 3, 实际: %d", stats.ErrorCount["reset"])
	}

	// 越界
	a.UpdateNetworkError(3, 999)
	a.UpdateNetworkError(-1, 999)
}

func TestReadFileStats_Initial(t *testing.T) {
	a := NewAggregator()
	stats := a.ReadFileStats()

	expectedKeys := []string{"critical_read", "critical_write", "warning_read", "warning_write", "info_read", "info_write"}
	for _, k := range expectedKeys {
		if _, ok := stats.AccessCount[k]; !ok {
			t.Errorf("AccessCount 缺少 key: %s", k)
		}
		if stats.AccessCount[k] != 0 {
			t.Errorf("初始 AccessCount[%s] 应为 0, 实际: %d", k, stats.AccessCount[k])
		}
	}
}

func TestUpdateFileAccess(t *testing.T) {
	a := NewAggregator()

	// critical_read = index 0, critical_write = index 1
	a.UpdateFileAccess(0, 42) // critical_read
	a.UpdateFileAccess(1, 7)  // critical_write
	stats := a.ReadFileStats()

	if stats.AccessCount["critical_read"] != 42 {
		t.Errorf("AccessCount[critical_read] 应为 42, 实际: %d", stats.AccessCount["critical_read"])
	}
	if stats.AccessCount["critical_write"] != 7 {
		t.Errorf("AccessCount[critical_write] 应为 7, 实际: %d", stats.AccessCount["critical_write"])
	}

	// 越界
	a.UpdateFileAccess(6, 999)
	a.UpdateFileAccess(-1, 999)
}

func TestReadPrivilegeStats_Initial(t *testing.T) {
	a := NewAggregator()
	stats := a.ReadPrivilegeStats()

	expectedKeys := []string{"setuid_success", "setuid_failure", "setgid_success", "setgid_failure", "capset_success", "capset_failure"}
	for _, k := range expectedKeys {
		if _, ok := stats.EscalationCount[k]; !ok {
			t.Errorf("EscalationCount 缺少 key: %s", k)
		}
		if stats.EscalationCount[k] != 0 {
			t.Errorf("初始 EscalationCount[%s] 应为 0, 实际: %d", k, stats.EscalationCount[k])
		}
	}
}

func TestUpdatePrivilege(t *testing.T) {
	a := NewAggregator()

	// setuid_success = index 0
	a.UpdatePrivilege(0, 15)
	// capset_failure = index 5
	a.UpdatePrivilege(5, 3)
	stats := a.ReadPrivilegeStats()

	if stats.EscalationCount["setuid_success"] != 15 {
		t.Errorf("EscalationCount[setuid_success] 应为 15, 实际: %d", stats.EscalationCount["setuid_success"])
	}
	if stats.EscalationCount["capset_failure"] != 3 {
		t.Errorf("EscalationCount[capset_failure] 应为 3, 实际: %d", stats.EscalationCount["capset_failure"])
	}

	// 越界
	a.UpdatePrivilege(6, 999)
	a.UpdatePrivilege(-1, 999)
}

func TestReadKernelStats_Initial(t *testing.T) {
	a := NewAggregator()
	stats := a.ReadKernelStats()

	expectedKeys := []string{"load", "load_file"}
	for _, k := range expectedKeys {
		if _, ok := stats.ModuleLoadCount[k]; !ok {
			t.Errorf("ModuleLoadCount 缺少 key: %s", k)
		}
		if stats.ModuleLoadCount[k] != 0 {
			t.Errorf("初始 ModuleLoadCount[%s] 应为 0, 实际: %d", k, stats.ModuleLoadCount[k])
		}
	}
}

func TestUpdateModuleLoad(t *testing.T) {
	a := NewAggregator()

	a.UpdateModuleLoad(0, 20) // load
	a.UpdateModuleLoad(1, 8)  // load_file
	stats := a.ReadKernelStats()

	if stats.ModuleLoadCount["load"] != 20 {
		t.Errorf("ModuleLoadCount[load] 应为 20, 实际: %d", stats.ModuleLoadCount["load"])
	}
	if stats.ModuleLoadCount["load_file"] != 8 {
		t.Errorf("ModuleLoadCount[load_file] 应为 8, 实际: %d", stats.ModuleLoadCount["load_file"])
	}

	// 越界
	a.UpdateModuleLoad(2, 999)
	a.UpdateModuleLoad(-1, 999)
}

func TestReset(t *testing.T) {
	a := NewAggregator()

	// 写入各种数据
	a.UpdateProcessCount(0, 10, 5, 5)
	a.UpdateProcessCount(2, 20, 3, 17)
	a.UpdateNetworkCount(0, 100, 50)
	a.UpdateNetworkError(1, 30)
	a.UpdateFileAccess(0, 99)
	a.UpdatePrivilege(3, 77)
	a.UpdateModuleLoad(1, 44)

	// Reset
	a.Reset()

	// 验证所有计数归零
	stats := a.ReadProcessStats()
	for cat, v := range stats.ExecCount {
		if v != 0 {
			t.Errorf("Reset 后 ExecCount[%s] 应为 0, 实际: %d", cat, v)
		}
	}

	netStats := a.ReadNetworkStats()
	for k, v := range netStats.ConnectTotal {
		if v != 0 {
			t.Errorf("Reset 后 ConnectTotal[%s] 应为 0, 实际: %d", k, v)
		}
	}
	for k, v := range netStats.ErrorCount {
		if v != 0 {
			t.Errorf("Reset 后 ErrorCount[%s] 应为 0, 实际: %d", k, v)
		}
	}

	fileStats := a.ReadFileStats()
	for k, v := range fileStats.AccessCount {
		if v != 0 {
			t.Errorf("Reset 后 AccessCount[%s] 应为 0, 实际: %d", k, v)
		}
	}

	privStats := a.ReadPrivilegeStats()
	for k, v := range privStats.EscalationCount {
		if v != 0 {
			t.Errorf("Reset 后 EscalationCount[%s] 应为 0, 实际: %d", k, v)
		}
	}

	kernelStats := a.ReadKernelStats()
	for k, v := range kernelStats.ModuleLoadCount {
		if v != 0 {
			t.Errorf("Reset 后 ModuleLoadCount[%s] 应为 0, 实际: %d", k, v)
		}
	}
}

func TestReset_ThenAccumulate(t *testing.T) {
	a := NewAggregator()
	a.UpdateProcessCount(0, 100, 0, 100)
	a.Reset()
	a.UpdateProcessCount(0, 5, 1, 4)

	stats := a.ReadProcessStats()
	if stats.ExecCount["system"] != 5 {
		t.Errorf("Reset 后再累积 ExecCount[system] 应为 5, 实际: %d", stats.ExecCount["system"])
	}
}
