package config

import (
	"flag"
	"log"
	"strings"

	"security-exporter/pkg/logger"
)

// Config 应用程序配置结构
type Config struct {
	ListenAddress string
	MetricsPath   string
	PortStates    []string
	LogLevel      string
	LogFormat     string
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
		logLevel      = flag.String("log.level", "info", "Set the logging level. One of: debug, info, warn, error.")
		logFormat     = flag.String("log.format", "logfmt", "Set the log format. One of: logfmt, json.")
	)

	flag.Parse()

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
		ListenAddress: *listenAddress,
		MetricsPath:   *metricsPath,
		PortStates:    states,
		LogLevel:      logLevelLower,
		LogFormat:     logFormatLower,
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
