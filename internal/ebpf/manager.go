// Package ebpf 提供 eBPF 程序的生命周期管理。
package ebpf

import (
	"context"

	_ "github.com/cilium/ebpf" // 确保 go mod tidy 保留依赖

	"security-exporter/pkg/logger"
)

// Manager 管理 eBPF 程序的生命周期
type Manager struct {
	enabled bool
	running bool
}

// NewManager 创建 eBPF Manager
func NewManager(enabled bool) *Manager {
	return &Manager{
		enabled: enabled,
	}
}

// Start 启动 eBPF 监控（检测可用性 → 加载程序 → 附加 tracepoints）
func (m *Manager) Start(ctx context.Context) error {
	if !m.enabled {
		logger.Info("eBPF monitoring is disabled")
		return nil
	}

	// TODO: 后续任务实现 BPF 程序加载
	// 1. CheckBPFAvailability()
	// 2. loadBpfPrograms()
	// 3. attachTracepoints()
	// 4. startAggregationGoroutine(ctx)

	logger.Info("eBPF manager started (placeholder - BPF programs not yet loaded)")
	m.running = true
	return nil
}

// Stop 停止 eBPF 监控（分离程序 → 关闭 maps → 清理资源）
func (m *Manager) Stop() {
	if !m.running {
		return
	}

	// TODO: 后续任务实现清理逻辑
	logger.Info("eBPF manager stopped")
	m.running = false
}

// IsRunning 返回 eBPF 是否正在运行
func (m *Manager) IsRunning() bool {
	return m.running
}

// Enabled 返回 eBPF 是否已启用
func (m *Manager) Enabled() bool {
	return m.enabled
}
