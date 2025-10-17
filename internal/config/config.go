package config

import (
	"flag"
	"strings"
)

// Config 应用程序配置结构
type Config struct {
	ListenAddress string
	MetricsPath   string
	PortStates    []string
}

// LevelFlagOptions represents allowed logging levels.
var LevelFlagOptions = []string{"debug", "info", "warn", "error"}

// FormatFlagOptions represents allowed formats.
var FormatFlagOptions = []string{"logfmt", "json"}

// LoadConfig 加载应用程序配置
func LoadConfig() *Config {
	var (
		listenAddress = flag.String("web.listen-address", ":9102", "Address to listen on for web interface and telemetry.")
		metricsPath   = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
		portStates    = flag.String("collector.port-states", "LISTEN", "Comma-separated list of TCP port states to collect (LISTEN,ESTABLISHED,SYN_SENT,SYN_RECV,FIN_WAIT1,FIN_WAIT2,TIME_WAIT,CLOSE,CLOSE_WAIT,LAST_ACK,CLOSING). Default: LISTEN only.")
	)

	flag.Parse()

	// 解析端口状态配置
	states := strings.Split(*portStates, ",")
	for i, state := range states {
		states[i] = strings.TrimSpace(strings.ToUpper(state))
	}

	return &Config{
		ListenAddress: *listenAddress,
		MetricsPath:   *metricsPath,
		PortStates:    states,
	}
}
