package config

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"security-exporter/pkg/logger"
)

// Config 应用程序配置结构
type Config struct {
	ListenAddress          string
	MetricsPath            string
	PortStates             []string
	LogLevel               string
	LogFormat              string
	ShowVersion            bool
	EnableGoMetrics        bool // 是否采集Go自身性能指标
	CollectServicesEnabled bool // 是否采集启用的服务（默认true）
	CollectServicesRunning bool // 是否采集运行中的服务（默认false）
}

// VersionInfo 版本信息结构
type VersionInfo struct {
	Version   string
	BuildDate string
	GitCommit string
	GoVersion string
}

// LevelFlagOptions represents allowed logging levels.
var LevelFlagOptions = []string{"debug", "info", "warn", "error"}

// FormatFlagOptions represents allowed formats.
var FormatFlagOptions = []string{"logfmt", "json"}

// 版本信息变量，在构建时通过 ldflags 设置
var (
	Version   = "dev"
	BuildDate = "unknown"
	GitCommit = "unknown"
	GoVersion = "unknown"
)

// LoadConfig 加载应用程序配置
func LoadConfig() *Config {
	var (
		listenAddress          = flag.String("web.listen-address", ":9102", "Address to listen on for web interface and telemetry.")
		metricsPath            = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
		portStates             = flag.String("collector.port-states", "LISTEN", "Comma-separated list of TCP port states to collect (LISTEN,ESTABLISHED,SYN_SENT,SYN_RECV,FIN_WAIT1,FIN_WAIT2,TIME_WAIT,CLOSE,CLOSE_WAIT,LAST_ACK,CLOSING). Default: LISTEN only.")
		logLevel               = flag.String("log.level", "info", "Set the logging level. One of: debug, info, warn, error.")
		logFormat              = flag.String("log.format", "logfmt", "Set the log format. One of: logfmt, json.")
		enableGoMetrics        = flag.Bool("collector.go-metrics", false, "Enable collection of Go runtime metrics (go_*).")
		collectServicesEnabled = flag.Bool("collector.services-enabled", true, "Collect services that are enabled. Default: true (only collect enabled services).")
		collectServicesRunning = flag.Bool("collector.services-running", false, "Collect services that are running. Default: false (exclude running services).")
		showVersion            = flag.Bool("version", false, "Show version information and exit.")
	)

	flag.Parse()

	// 检查版本参数
	if *showVersion {
		PrintVersion()
		return nil
	}

	// 解析端口状态配置
	states := strings.Split(*portStates, ",")
	for i, state := range states {
		states[i] = strings.TrimSpace(strings.ToUpper(state))
	}

	// 验证日志级别
	logLevelLower := strings.ToLower(*logLevel)
	if !isValidLogLevel(logLevelLower) {
		log.Fatalf("Invalid log level: %s. Must be one of: %s", *logLevel, strings.Join(LevelFlagOptions, ", "))
	}

	// 验证日志格式
	logFormatLower := strings.ToLower(*logFormat)
	if !isValidLogFormat(logFormatLower) {
		log.Fatalf("Invalid log format: %s. Must be one of: %s", *logFormat, strings.Join(FormatFlagOptions, ", "))
	}

	// 配置日志
	logger.InitLogger(logLevelLower, logFormatLower)

	return &Config{
		ListenAddress:          *listenAddress,
		MetricsPath:            *metricsPath,
		PortStates:             states,
		LogLevel:               logLevelLower,
		LogFormat:              logFormatLower,
		EnableGoMetrics:        *enableGoMetrics,
		CollectServicesEnabled: *collectServicesEnabled,
		CollectServicesRunning: *collectServicesRunning,
		ShowVersion:            *showVersion,
	}
}

// isValidLogLevel 验证日志级别是否有效
func isValidLogLevel(level string) bool {
	for _, validLevel := range LevelFlagOptions {
		if level == validLevel {
			return true
		}
	}
	return false
}

// isValidLogFormat 验证日志格式是否有效
func isValidLogFormat(format string) bool {
	for _, validFormat := range FormatFlagOptions {
		if format == validFormat {
			return true
		}
	}
	return false
}

// PrintVersion 打印版本信息
func PrintVersion() {
	fmt.Printf("Security Exporter\n")
	fmt.Printf("Version: %s\n", Version)
	fmt.Printf("Build Date: %s\n", BuildDate)
	fmt.Printf("Git Commit: %s\n", GitCommit)
	fmt.Printf("Go Version: %s\n", GoVersion)
}
