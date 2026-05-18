package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestNewAggregator(t *testing.T) {
	a := NewAggregator()
	if a == nil {
		t.Fatal("NewAggregator() 返回 nil")
	}
}

func TestSetMaps(t *testing.T) {
	a := NewAggregator()

	// 创建 BpfMaps 结构（所有 map 为 nil）
	maps := &BpfMaps{}
	a.SetMaps(maps)

	// 验证 map 指针已设置（都是 nil 但字段不为 nil pointer）
	if a.processExecCount != nil {
		t.Error("未设置时 processExecCount 应为 nil")
	}
}

func TestSetMaps_NilReceiver(t *testing.T) {
	a := NewAggregator()

	// 不调用 SetMaps，所有 map 应为 nil
	maps := &BpfMaps{}
	a.SetMaps(maps)

	// nil maps → Read 方法应返回零值
	stats := a.ReadProcessStats()
	for _, cat := range []string{"system", "user", "container", "suspicious"} {
		if stats.ExecCount[cat] != 0 {
			t.Errorf("无 map 时 ExecCount[%s] 应为 0, 实际: %d", cat, stats.ExecCount[cat])
		}
		if stats.ExitCount[cat] != 0 {
			t.Errorf("无 map 时 ExitCount[%s] 应为 0, 实际: %d", cat, stats.ExitCount[cat])
		}
		if stats.ActiveCount[cat] != 0 {
			t.Errorf("无 map 时 ActiveCount[%s] 应为 0, 实际: %d", cat, stats.ActiveCount[cat])
		}
	}
}

func TestReadProcessStats_Keys(t *testing.T) {
	a := NewAggregator()
	a.SetMaps(&BpfMaps{})

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
	}
}

func TestReadNetworkStats_Keys(t *testing.T) {
	a := NewAggregator()
	a.SetMaps(&BpfMaps{})

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

func TestReadFileStats_Keys(t *testing.T) {
	a := NewAggregator()
	a.SetMaps(&BpfMaps{})

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

func TestReadPrivilegeStats_Keys(t *testing.T) {
	a := NewAggregator()
	a.SetMaps(&BpfMaps{})

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

func TestReadKernelStats_Keys(t *testing.T) {
	a := NewAggregator()
	a.SetMaps(&BpfMaps{})

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

func TestReadPercpuUint64_NilMap(t *testing.T) {
	// nil map 应返回 0 且不 panic
	val, err := readPercpuUint64(nil, 0)
	if err != nil {
		t.Errorf("nil map 不应返回错误, got: %v", err)
	}
	if val != 0 {
		t.Errorf("nil map 应返回 0, 实际: %d", val)
	}
}

func TestReadAndUpdateFromMaps_NilMaps(t *testing.T) {
	a := NewAggregator()
	a.SetMaps(&BpfMaps{})

	// 所有 map 为 nil，应返回 0 且不 panic
	total := a.ReadAndUpdateFromMaps()
	if total != 0 {
		t.Errorf("所有 map 为 nil 时总事件应为 0, 实际: %d", total)
	}
}

func TestReadAndUpdateFromMaps_NoSetMaps(t *testing.T) {
	a := NewAggregator()
	// 未调用 SetMaps，所有 map 为 nil
	total := a.ReadAndUpdateFromMaps()
	if total != 0 {
		t.Errorf("未设置 map 时总事件应为 0, 实际: %d", total)
	}
}

func TestBpfMaps_AllFields(t *testing.T) {
	// 验证 BpfMaps 结构包含所有必要的字段
	maps := &BpfMaps{
		ProcessExecCount:  (*ebpf.Map)(nil),
		ProcessExitCount:  (*ebpf.Map)(nil),
		ProcessActive:     (*ebpf.Map)(nil),
		ConnectTotal:      (*ebpf.Map)(nil),
		ConnectActive:     (*ebpf.Map)(nil),
		ConnectErrorTotal: (*ebpf.Map)(nil),
		FileAccessTotal:   (*ebpf.Map)(nil),
		PrivilegeTotal:    (*ebpf.Map)(nil),
		ModuleLoadTotal:   (*ebpf.Map)(nil),
	}

	a := NewAggregator()
	a.SetMaps(maps)

	// 应返回零值且不 panic
	ps := a.ReadProcessStats()
	ns := a.ReadNetworkStats()
	fs := a.ReadFileStats()
	prs := a.ReadPrivilegeStats()
	ks := a.ReadKernelStats()

	for _, cat := range []string{"system", "user", "container", "suspicious"} {
		if ps.ExecCount[cat] != 0 {
			t.Errorf("nil map ExecCount[%s] 应为 0", cat)
		}
	}
	for _, k := range []string{"in_tcp", "in_udp", "out_tcp", "out_udp"} {
		if ns.ConnectTotal[k] != 0 {
			t.Errorf("nil map ConnectTotal[%s] 应为 0", k)
		}
	}
	for _, k := range []string{"critical_read", "warning_read", "info_read"} {
		if fs.AccessCount[k] != 0 {
			t.Errorf("nil map AccessCount[%s] 应为 0", k)
		}
	}
	for _, k := range []string{"setuid_success", "capset_failure"} {
		if prs.EscalationCount[k] != 0 {
			t.Errorf("nil map EscalationCount[%s] 应为 0", k)
		}
	}
	for _, k := range []string{"load", "load_file"} {
		if ks.ModuleLoadCount[k] != 0 {
			t.Errorf("nil map ModuleLoadCount[%s] 应为 0", k)
		}
	}
}
