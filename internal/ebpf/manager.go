// Package ebpf 提供 eBPF 程序的生命周期管理。
package ebpf

import (
	"context"
	"fmt"
	"time"

	_ "github.com/cilium/ebpf" // 确保 go mod tidy 保留依赖

	"security-exporter/pkg/logger"
)

// Manager 管理 eBPF 程序的生命周期
type Manager struct {
	enabled    bool
	running    bool
	aggregator *Aggregator
	cancel    context.CancelFunc
}

// NewManager 创建 eBPF Manager
func NewManager(enabled bool) *Manager {
	return &Manager{
		enabled:    enabled,
		aggregator: NewAggregator(),
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

	// 启动模拟聚合 goroutine
	// 后续任务将替换为真实 BPF 程序加载:
	// 1. loadBpfPrograms() — 使用 bpf2go 生成的代码加载 BPF 对象
	// 2. attachTracepoints() — 附加到内核 tracepoint
	// 3. startAggregationGoroutine(ctx) — 从 BPF maps 读取聚合数据
	subCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.startSimulationLoop(subCtx)

	m.running = true
	logger.Info("eBPF manager started (simulation mode)")
	return nil
}

// Stop 停止 eBPF 监控（分离程序 → 关闭 maps → 清理资源）
func (m *Manager) Stop() {
	if !m.running {
		return
	}

	if m.cancel != nil {
		m.cancel()
	}
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

// Aggregator 返回聚合器实例
func (m *Manager) Aggregator() *Aggregator {
	return m.aggregator
}

// startSimulationLoop 启动模拟数据生成循环
// 后续替换为真实 BPF map 读取时删除此方法
func (m *Manager) startSimulationLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// 模拟更新：增量写入聚合器
				// 真实模式下，这里从 BPF percpu_array map 读取并重置
				m.aggregator.UpdateProcessCount(0, 1, 0, 1) // system
				m.aggregator.UpdateProcessCount(1, 2, 1, 1) // user
			}
		}
	}()
}
