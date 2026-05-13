package system

import (
	"os"
	"security-exporter/pkg/logger"
	"strings"
)

// CrontabEntryInfo crontab条目信息
type CrontabEntryInfo struct {
	User     string // 用户
	Schedule string // 调度时间
	Command  string // 命令
	Source   string // 来源文件
	IsSystem bool   // 是否系统crontab
}

// GetAllCrontabInfo 获取所有crontab条目
func GetAllCrontabInfo() []CrontabEntryInfo {
	logger.Debug("GetAllCrontabInfo: 开始获取crontab信息")

	var entries []CrontabEntryInfo

	// 解析 /etc/crontab (系统crontab)
	entries = append(entries, parseCrontabFile("/etc/crontab", true)...)

	// 解析 /etc/cron.d/* (系统cron目录)
	cronDFiles, err := os.ReadDir("/etc/cron.d")
	if err == nil {
		for _, f := range cronDFiles {
			if !f.IsDir() {
				path := "/etc/cron.d/" + f.Name()
				entries = append(entries, parseCrontabFile(path, true)...)
			}
		}
	} else {
		logger.Debug("GetAllCrontabInfo: 读取 /etc/cron.d 目录失败: %v", err)
	}

	// 解析 /var/spool/cron/* (用户crontab)
	userCronFiles, err := os.ReadDir("/var/spool/cron")
	if err == nil {
		for _, f := range userCronFiles {
			if !f.IsDir() {
				path := "/var/spool/cron/" + f.Name()
				entries = append(entries, parseUserCrontab(path, f.Name())...)
			}
		}
	} else {
		logger.Debug("GetAllCrontabInfo: 读取 /var/spool/cron 目录失败: %v", err)
	}

	logger.Debug("GetAllCrontabInfo: 共找到 %d 个crontab条目", len(entries))
	return entries
}

func parseCrontabFile(path string, isSystem bool) []CrontabEntryInfo {
	data, err := os.ReadFile(path)
	if err != nil {
		logger.Debug("parseCrontabFile: 读取文件失败 %s: %v", path, err)
		return nil
	}

	var entries []CrontabEntryInfo
	for _, line := range strings.Split(string(data), "\n") {
		if entry, ok := parseCrontabLine(line, path, isSystem); ok {
			entries = append(entries, entry)
		}
	}
	return entries
}

// parseUserCrontab 解析用户crontab文件
// 用户crontab格式: 分 时 日 月 周 命令 (6个字段，无用户列)
func parseUserCrontab(path string, user string) []CrontabEntryInfo {
	data, err := os.ReadFile(path)
	if err != nil {
		logger.Debug("parseUserCrontab: 读取文件失败 %s: %v", path, err)
		return nil
	}

	var entries []CrontabEntryInfo
	for _, line := range strings.Split(string(data), "\n") {
		if entry, ok := parseCrontabLine(line, path, false); ok {
			entry.User = user
			entries = append(entries, entry)
		}
	}
	return entries
}


// parseCrontabLine 解析单行crontab内容
// isSystem=true 时期望7个字段（含用户列），isSystem=false 时期望6个字段
func parseCrontabLine(line string, source string, isSystem bool) (CrontabEntryInfo, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return CrontabEntryInfo{}, false
	}

	fields := strings.Fields(line)

	minFields := 7
	if !isSystem {
		minFields = 6
	}
	if len(fields) < minFields {
		return CrontabEntryInfo{}, false
	}

	if !isValidTimeField(fields[0]) {
		return CrontabEntryInfo{}, false
	}

	schedule := fields[0] + " " + fields[1] + " " + fields[2] + " " + fields[3] + " " + fields[4]

	if isSystem {
		return CrontabEntryInfo{
			User:     fields[5],
			Schedule: schedule,
			Command:  strings.Join(fields[6:], " "),
			Source:   source,
			IsSystem: true,
		}, true
	}

	// 用户crontab：从 source 路径提取用户名
	user := ""
	parts := strings.Split(source, "/")
	if len(parts) > 0 {
		user = parts[len(parts)-1]
	}
	return CrontabEntryInfo{
		User:     user,
		Schedule: schedule,
		Command:  strings.Join(fields[5:], " "),
		Source:   source,
		IsSystem: false,
	}, true
}

// isValidTimeField 检查是否为有效的cron时间字段
func isValidTimeField(field string) bool {
	if field == "" {
		return false
	}
	// 时间字段可以包含数字、*、,、-、/
	for _, c := range field {
		if !((c >= '0' && c <= '9') || c == '*' || c == ',' || c == '-' || c == '/') {
			return false
		}
	}
	return true
}
