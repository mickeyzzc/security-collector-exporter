package collector

import (
	"strings"
	"sync"

	"security-exporter/internal/ebpf"

	"github.com/prometheus/client_golang/prometheus"
)

// EbpfCollector eBPF 安全事件 Prometheus collector
type EbpfCollector struct {
	mu         sync.Mutex
	aggregator *ebpf.Aggregator
	enabled    bool
	running    bool

	// 进程指标
	processExecTotal   *prometheus.Desc
	processExitTotal   *prometheus.Desc
	processActiveCount *prometheus.Desc

	// 网络指标
	connectTotal      *prometheus.Desc
	connectActive     *prometheus.Desc
	connectErrorTotal *prometheus.Desc

	// 文件访问指标
	fileAccessTotal *prometheus.Desc

	// 提权指标
	privilegeEscTotal *prometheus.Desc

	// 内核模块指标
	kernelModuleTotal *prometheus.Desc

	// 元信息
	ebpfUp     *prometheus.Desc
	sampleRate *prometheus.Desc
	// 获取动态采样率的回调函数
	sampleRateGetter func() uint64
}

// NewEbpfCollector 创建 eBPF collector
func NewEbpfCollector(aggregator *ebpf.Aggregator, enabled, running bool, sampleRateGetter func() uint64) *EbpfCollector {
	return &EbpfCollector{
		aggregator: aggregator,
		enabled:    enabled,
		running:    running,
		sampleRateGetter: sampleRateGetter,

		// 进程指标（标签: type, 基数=4: system/user/container/suspicious）
		processExecTotal: prometheus.NewDesc(
			"security_ebpf_process_exec_total",
			"Total number of process executions tracked by eBPF, classified by type",
			[]string{"type"}, nil,
		),
		processExitTotal: prometheus.NewDesc(
			"security_ebpf_process_exit_total",
			"Total number of process exits tracked by eBPF",
			[]string{"type"}, nil,
		),
		processActiveCount: prometheus.NewDesc(
			"security_ebpf_process_active_count",
			"Current number of active processes by type",
			[]string{"type"}, nil,
		),

		// 网络指标（标签: direction+protocol, 基数=2×2=4; 错误 type 基数=3）
		connectTotal: prometheus.NewDesc(
			"security_ebpf_connect_total",
			"Total number of network connections tracked by eBPF",
			[]string{"direction", "protocol"}, nil,
		),
		connectActive: prometheus.NewDesc(
			"security_ebpf_connect_active",
			"Current number of active network connections",
			[]string{"direction", "protocol"}, nil,
		),
		connectErrorTotal: prometheus.NewDesc(
			"security_ebpf_connect_error_total",
			"Total number of network connection errors",
			[]string{"type"}, nil,
		),

		// 文件访问（标签: severity+operation, 基数=3×2=6）
		fileAccessTotal: prometheus.NewDesc(
			"security_ebpf_file_access_total",
			"Total number of sensitive file accesses tracked by eBPF",
			[]string{"severity", "operation"}, nil,
		),

		// 提权（标签: type+result, 基数=3×2=6）
		privilegeEscTotal: prometheus.NewDesc(
			"security_ebpf_privilege_escalation_total",
			"Total number of privilege escalation attempts tracked by eBPF",
			[]string{"type", "result"}, nil,
		),

		// 内核模块（标签: action, 基数=2）
		kernelModuleTotal: prometheus.NewDesc(
			"security_ebpf_kernel_module_total",
			"Total number of kernel module operations tracked by eBPF",
			[]string{"action"}, nil,
		),

		// 元信息
		ebpfUp: prometheus.NewDesc(
			"security_ebpf_up",
			"Whether eBPF monitoring is active (1=active, 0=disabled/degraded)",
			[]string{"status"}, nil,
		),
		sampleRate: prometheus.NewDesc(
			"security_ebpf_sample_rate",
			"Current eBPF event sampling rate",
			nil, nil,
		),
	}
}

// Describe 实现 prometheus.Collector
func (c *EbpfCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.processExecTotal
	ch <- c.processExitTotal
	ch <- c.processActiveCount
	ch <- c.connectTotal
	ch <- c.connectActive
	ch <- c.connectErrorTotal
	ch <- c.fileAccessTotal
	ch <- c.privilegeEscTotal
	ch <- c.kernelModuleTotal
	ch <- c.ebpfUp
	ch <- c.sampleRate
}

// Collect 实现 prometheus.Collector
func (c *EbpfCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 状态指标
	switch {
	case c.running:
		ch <- prometheus.MustNewConstMetric(c.ebpfUp, prometheus.GaugeValue, 1, "active")
	case c.enabled:
		ch <- prometheus.MustNewConstMetric(c.ebpfUp, prometheus.GaugeValue, 0, "degraded")
	default:
		ch <- prometheus.MustNewConstMetric(c.ebpfUp, prometheus.GaugeValue, 0, "disabled")
		return
	}

	// 采样率
	rate := uint64(1)
	if c.sampleRateGetter != nil {
		rate = c.sampleRateGetter()
	}
	ch <- prometheus.MustNewConstMetric(c.sampleRate, prometheus.GaugeValue, float64(rate))

	// 如果未运行（降级模式），不暴露数据指标
	if !c.running {
		return
	}

	// 进程指标
	ps := c.aggregator.ReadProcessStats()
	for t, v := range ps.ExecCount {
		ch <- prometheus.MustNewConstMetric(c.processExecTotal, prometheus.CounterValue, float64(v), t)
	}
	for t, v := range ps.ExitCount {
		ch <- prometheus.MustNewConstMetric(c.processExitTotal, prometheus.CounterValue, float64(v), t)
	}
	for t, v := range ps.ActiveCount {
		ch <- prometheus.MustNewConstMetric(c.processActiveCount, prometheus.GaugeValue, float64(v), t)
	}

	// 网络指标
	ns := c.aggregator.ReadNetworkStats()
	for k, v := range ns.ConnectTotal {
		parts := strings.SplitN(k, "_", 2)
		if len(parts) == 2 {
			ch <- prometheus.MustNewConstMetric(c.connectTotal, prometheus.CounterValue, float64(v), parts[0], parts[1])
		}
	}
	for k, v := range ns.ConnectActive {
		parts := strings.SplitN(k, "_", 2)
		if len(parts) == 2 {
			ch <- prometheus.MustNewConstMetric(c.connectActive, prometheus.GaugeValue, float64(v), parts[0], parts[1])
		}
	}
	for t, v := range ns.ErrorCount {
		ch <- prometheus.MustNewConstMetric(c.connectErrorTotal, prometheus.CounterValue, float64(v), t)
	}

	// 文件访问指标
	fs := c.aggregator.ReadFileStats()
	for k, v := range fs.AccessCount {
		parts := strings.SplitN(k, "_", 2)
		if len(parts) == 2 {
			ch <- prometheus.MustNewConstMetric(c.fileAccessTotal, prometheus.CounterValue, float64(v), parts[0], parts[1])
		}
	}

	// 提权指标
	prs := c.aggregator.ReadPrivilegeStats()
	for k, v := range prs.EscalationCount {
		parts := strings.SplitN(k, "_", 2)
		if len(parts) == 2 {
			ch <- prometheus.MustNewConstMetric(c.privilegeEscTotal, prometheus.CounterValue, float64(v), parts[0], parts[1])
		}
	}

	// 内核模块指标
	ks := c.aggregator.ReadKernelStats()
	for a, v := range ks.ModuleLoadCount {
		ch <- prometheus.MustNewConstMetric(c.kernelModuleTotal, prometheus.CounterValue, float64(v), a)
	}
}
