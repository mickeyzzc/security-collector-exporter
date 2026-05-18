// Package main 是 Linux 安全信息 Prometheus Exporter 的入口。
package main

import (
	"context"
	"log"
	"net/http"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"security-exporter/internal/collector"
	"security-exporter/internal/ebpf"
	"security-exporter/pkg/config"
)

func main() {
	// 加载配置（包含日志配置）
	cfg := config.LoadConfig()

	// 如果配置为nil，说明显示了版本信息，直接退出
	if cfg == nil {
		return
	}

	// 创建带取消的 context，监听系统信号用于优雅关闭
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 如果启用Go性能指标，注册Go runtime collector
	if cfg.EnableGoMetrics {
		prometheus.MustRegister(collectors.NewGoCollector())
	}

	// 创建收集器并注册
	securityCollector := collector.NewSecurityCollector(cfg)
	prometheus.MustRegister(securityCollector)

	// 初始化 eBPF Manager
	ebpfManager := ebpf.NewManager(cfg.EbpfEnabled)
	if err := ebpfManager.Start(ctx); err != nil {
		log.Printf("Failed to start eBPF manager: %v", err)
		stop()
		return
	}
	defer ebpfManager.Stop()

	// 创建并注册 eBPF collector（始终注册，由 collector 内部根据 enabled/running 状态决定输出）
	ebpfCollector := collector.NewEbpfCollector(ebpfManager.Aggregator(), ebpfManager.Enabled(), ebpfManager.IsRunning())
	prometheus.MustRegister(ebpfCollector)

	// 注册metrics处理器
	http.Handle(cfg.MetricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html>
			<head><title>Linux Security Exporter</title></head>
			<body>
			<h1>Linux Security Exporter</h1>
			<p>针对安全策略相关的采集</p>
			<p><a href="` + cfg.MetricsPath + `">Metrics</a></p>
			</body>
			</html>`))
	})

	// 在独立 goroutine 中启动 HTTP server
	serverErr := make(chan error, 1)
	go func() {
		log.Printf("Starting exporter on %s", cfg.ListenAddress)
		// #nosec G114 -- Prometheus exporter 标准模式，通过外部 supervisor 控制超时
		if err := http.ListenAndServe(cfg.ListenAddress, nil); err != nil {
			serverErr <- err
		}
	}()

	// 等待关闭信号或 server 错误
	select {
	case <-ctx.Done():
		log.Println("Received shutdown signal, gracefully stopping...")
	case err := <-serverErr:
		log.Printf("Server error: %v", err)
		stop()
		return
	}

	// 优雅关闭：eBPF Manager Stop 通过 defer 调用
	log.Println("Exporter stopped")
}
