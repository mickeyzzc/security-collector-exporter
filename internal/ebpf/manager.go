// Package ebpf 提供 eBPF 程序的生命周期管理。
package ebpf

import (
	"context"
	"fmt"

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

	// 检查 BPF 可用性
	avail := CheckBPFAvailability()
	if !avail.Available {
		logger.Warn("eBPF monitoring degraded, reasons:")
		for _, r := range avail.Reasons {
			logger.Warn(fmt.Sprintf("  - %s", r))
		}
		logger.Warn("Continuing with traditional collectors only")
		return nil
	}

	logger.Info("eBPF environment check passed")
	// TODO: 后续任务实现 BPF 程序加载
	// 1. loadBpfPrograms()
	// 2. attachTracepoints()
	// 3. startAggregationGoroutine(ctx)

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
