// Package ebpf 提供 eBPF 程序的生命周期管理。
package ebpf

import (
	"context"
	"fmt"
	"time"

	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"security-exporter/internal/bpf"
	"security-exporter/pkg/config"
	"security-exporter/pkg/logger"
)

// closeAll 关闭所有 BPF 对象，忽略错误（用于 loadBpfPrograms 的回滚路径）
func closeAll(closers ...io.Closer) {
	for _, c := range closers {
		if c != nil {
			_ = c.Close()
		}
	}
}

// Manager 管理 eBPF 程序的生命周期
type Manager struct {
	enabled    bool
	running    bool
	aggregator *Aggregator
	cancel     context.CancelFunc
	sampler    *AdaptiveSampler
	cfg        *config.Config

	// BPF 对象（程序 + maps）
	processObjs  bpf.BpfProcessObjects
	networkObjs  bpf.BpfNetworkObjects
	fileObjs     bpf.BpfFileObjects
	privilegeObjs bpf.BpfPrivilegeObjects
	kernelObjs   bpf.BpfKernelObjects

	// 所有已附加的 link，用于关闭时清理
	links []link.Link
}

// NewManager 创建 eBPF Manager
func NewManager(cfg *config.Config) *Manager {
	maxEps := cfg.EbpfMaxEventsPerSec
	if maxEps <= 0 {
		maxEps = 5000
	}
	return &Manager{
		enabled:    cfg.EbpfEnabled,
		cfg:        cfg,
		aggregator: NewAggregator(),
		sampler:    NewAdaptiveSampler(maxEps),
	}
}

// Start 启动 eBPF 监控（检测可用性 → 提升权限 → 加载程序 → 附加 tracepoints → 启动聚合循环）
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

	// 提升内存锁限制，允许 BPF 程序加载
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock limit: %w", err)
	}

	// 加载所有 BPF 程序
	if err := m.loadBpfPrograms(); err != nil {
		return fmt.Errorf("load BPF programs: %w", err)
	}
	logger.Info("BPF programs loaded successfully")

	// 附加所有 tracepoints 和 kprobes
	if err := m.attachTracepoints(); err != nil {
		return fmt.Errorf("attach tracepoints: %w", err)
	}
	logger.Info("BPF tracepoints attached successfully")

	// 将 BPF maps 注入聚合器
	m.aggregator.SetMaps(&BpfMaps{
		ProcessExecCount:  m.processObjs.ExecCategoryCount,
		ProcessExitCount:  m.processObjs.ExitCategoryCount,
		ProcessActive:     m.processObjs.ActiveProcessCount,
		ConnectTotal:      m.networkObjs.ConnectTotal,
		ConnectActive:     m.networkObjs.ConnectActive,
		ConnectErrorTotal: m.networkObjs.ConnectErrorTotal,
		FileAccessTotal:   m.fileObjs.FileAccessTotal,
		PrivilegeTotal:    m.privilegeObjs.PrivilegeEscalationTotal,
		ModuleLoadTotal:   m.kernelObjs.ModuleLoadTotal,
	})

	// 启动周期性 map 读取 goroutine
	subCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.startMapReaderLoop(subCtx)

	m.running = true
	logger.Info("eBPF manager started")
	return nil
}

// loadBpfPrograms 加载所有 5 组 BPF 程序到内核
func (m *Manager) loadBpfPrograms() error {
	// 加载进程监控 BPF
	if err := bpf.LoadBpfProcessObjects(&m.processObjs, nil); err != nil {
		return fmt.Errorf("load process BPF: %w", err)
	}

	// 加载网络监控 BPF
	if err := bpf.LoadBpfNetworkObjects(&m.networkObjs, nil); err != nil {
		closeAll(&m.processObjs)
		return fmt.Errorf("load network BPF: %w", err)
	}

	// 加载文件访问监控 BPF
	if err := bpf.LoadBpfFileObjects(&m.fileObjs, nil); err != nil {
		closeAll(&m.processObjs, &m.networkObjs)
		return fmt.Errorf("load file BPF: %w", err)
	}

	// 加载提权监控 BPF
	if err := bpf.LoadBpfPrivilegeObjects(&m.privilegeObjs, nil); err != nil {
		closeAll(&m.processObjs, &m.networkObjs, &m.fileObjs)
		return fmt.Errorf("load privilege BPF: %w", err)
	}

	// 加载内核模块监控 BPF
	if err := bpf.LoadBpfKernelObjects(&m.kernelObjs, nil); err != nil {
		closeAll(&m.processObjs, &m.networkObjs, &m.fileObjs, &m.privilegeObjs)
		return fmt.Errorf("load kernel BPF: %w", err)
	}

	return nil
}

// attachTracepoints 将所有 BPF 程序附加到对应的内核 tracepoint/kprobe
func (m *Manager) attachTracepoints() error {
	var attachErr error

	// 辅助函数：附加 tracepoint，出错时记录但继续
	attachTracepoint := func(group, name string, prog *ebpf.Program) {
		if prog == nil {
			return
		}
		l, err := link.Tracepoint(group, name, prog, nil)
		if err != nil {
			logger.Warn(fmt.Sprintf("attach tracepoint %s/%s: %v", group, name, err))
			return
		}
		m.links = append(m.links, l)
	}

	// 进程 tracepoints
	attachTracepoint("syscalls", "sys_enter_execve", m.processObjs.TraceExecve)
	attachTracepoint("sched", "sched_process_exit", m.processObjs.TraceProcessExit)

	// 网络 tracepoints
	attachTracepoint("sock", "inet_sock_set_state", m.networkObjs.TraceTcpStateChange)

	// 文件 tracepoints
	attachTracepoint("syscalls", "sys_enter_openat", m.fileObjs.TraceOpenat)

	// 提权 tracepoints
	attachTracepoint("syscalls", "sys_enter_setuid", m.privilegeObjs.TraceSetuidEnter)
	attachTracepoint("syscalls", "sys_exit_setuid", m.privilegeObjs.TraceSetuidExit)
	attachTracepoint("syscalls", "sys_enter_setgid", m.privilegeObjs.TraceSetgidEnter)
	attachTracepoint("syscalls", "sys_exit_setgid", m.privilegeObjs.TraceSetgidExit)
	attachTracepoint("syscalls", "sys_enter_capset", m.privilegeObjs.TraceCapsetEnter)
	attachTracepoint("syscalls", "sys_exit_capset", m.privilegeObjs.TraceCapsetExit)

	// 内核模块 tracepoints
	attachTracepoint("syscalls", "sys_enter_init_module", m.kernelObjs.TraceInitModule)
	attachTracepoint("syscalls", "sys_enter_finit_module", m.kernelObjs.TraceFinitModule)

	return attachErr
}

// startMapReaderLoop 启动周期性 BPF map 读取 goroutine
func (m *Manager) startMapReaderLoop(ctx context.Context) {
	go func() {
		// 每 5 秒读取一次 BPF maps
		ticker := newTicker(5)
		defer ticker.stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.ch():
				// 从 BPF percpu_array maps 读取聚合数据
				totalEvents := m.aggregator.ReadAndUpdateFromMaps()

				// 更新自适应采样器
				m.sampler.Record(totalEvents)
				m.sampler.Adjust()
			}
		}
	}()
}


// realTicker 基于 time.Ticker 的实现
type realTicker struct {
	inner chan struct{}
	done  chan struct{}
}

func newTicker(seconds int) *realTicker {
	rt := &realTicker{
		inner: make(chan struct{}),
		done:  make(chan struct{}),
	}
	go func() {
		defer close(rt.inner)
		t := time.NewTicker(time.Duration(seconds) * time.Second)
		defer t.Stop()
		for {
			select {
			case <-rt.done:
				return
			case <-t.C:
				rt.inner <- struct{}{}
			}
		}
	}()
	return rt
}

func (t *realTicker) ch() <-chan struct{}  { return t.inner }
func (t *realTicker) stop()                 { close(t.done) }

// Stop 停止 eBPF 监控（分离程序 → 关闭 maps → 清理资源）
func (m *Manager) Stop() {
	if !m.running {
		return
	}

	// 取消上下文，停止 map 读取 goroutine
	if m.cancel != nil {
		m.cancel()
	}

	// 关闭所有 link（分离 tracepoint/kprobe）
	for _, l := range m.links {
		_ = l.Close()
	}
	m.links = nil

	closeAll(
		&m.kernelObjs,
		&m.privilegeObjs,
		&m.fileObjs,
		&m.networkObjs,
		&m.processObjs,
	)

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

// SampleRate 返回当前自适应采样率
func (m *Manager) SampleRate() uint64 {
	if m.sampler == nil {
		return 1
	}
	return m.sampler.SampleRate()
}
