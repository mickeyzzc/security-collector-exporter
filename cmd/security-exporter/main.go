package main

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"security-exporter/internal/collector"
	"security-exporter/pkg/config"
)

func main() {
	// 加载配置（包含日志配置）
	cfg := config.LoadConfig()

	// 如果配置为nil，说明显示了版本信息，直接退出
	if cfg == nil {
		return
	}

	// 如果启用Go性能指标，注册Go runtime collector
	if cfg.EnableGoMetrics {
		prometheus.MustRegister(prometheus.NewGoCollector())
	}

	// 创建收集器并注册
	securityCollector := collector.NewSecurityCollector(cfg)
	prometheus.MustRegister(securityCollector)

	// 注册metrics处理器
	http.Handle(cfg.MetricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>Linux Security Exporter</title></head>
			<body>
			<h1>Linux Security Exporter</h1>
			<p>针对安全策略相关的采集</p>
			<p><a href="` + cfg.MetricsPath + `">Metrics</a></p>
			</body>
			</html>`))
	})

	log.Printf("Starting exporter on %s", cfg.ListenAddress)
	if err := http.ListenAndServe(cfg.ListenAddress, nil); err != nil {
		log.Fatalf("Failed to start exporter: %v", err)
	}
}
