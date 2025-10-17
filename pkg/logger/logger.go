package logger

import (
	"log"
	"os"
)

var (
	// DebugEnabled 控制是否输出debug日志
	DebugEnabled bool
)

// InitLogger 初始化日志系统
func InitLogger(level, format string) {
	// 设置日志输出到标准输出
	log.SetOutput(os.Stdout)

	// 根据级别设置debug模式
	DebugEnabled = (level == "debug")

	// 根据格式设置日志前缀
	if format == "json" {
		// JSON格式暂时使用默认格式，可以后续扩展
		log.SetFlags(0)
	} else {
		// logfmt格式
		log.SetFlags(log.LstdFlags)
	}

	// 根据级别设置日志输出
	switch level {
	case "debug":
		// debug级别输出所有日志，包含文件名和行号
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	case "info":
		// info级别输出标准日志
		log.SetFlags(log.LstdFlags)
	case "warn", "error":
		// warn和error级别输出标准日志
		log.SetFlags(log.LstdFlags)
	}
}

// Debug 输出debug级别日志
func Debug(format string, v ...interface{}) {
	if DebugEnabled {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// Info 输出info级别日志
func Info(format string, v ...interface{}) {
	log.Printf("[INFO] "+format, v...)
}

// Warn 输出warn级别日志
func Warn(format string, v ...interface{}) {
	log.Printf("[WARN] "+format, v...)
}

// Error 输出error级别日志
func Error(format string, v ...interface{}) {
	log.Printf("[ERROR] "+format, v...)
}
