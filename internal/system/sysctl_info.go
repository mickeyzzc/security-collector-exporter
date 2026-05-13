// Package system 采集 Linux 系统安全相关信息，包括账户、SSH、防火墙、端口、服务等指标。
package system

import (
	"os"
	"security-exporter/pkg/logger"
	"strings"
)

// SysctlParamInfo sysctl安全参数信息
type SysctlParamInfo struct {
	Name          string // 参数名
	Value         string // 当前值
	ExpectedValue string // 期望值
	IsSecure      bool   // 是否符合安全要求
}

// GetSysctlSecurityParams 获取内核安全参数
func GetSysctlSecurityParams() []SysctlParamInfo {
	logger.Debug("GetSysctlSecurityParams: 开始获取内核安全参数")

	params := []struct {
		name          string
		expectedValue string
	}{
		{"net.ipv4.ip_forward", "0"},
		{"net.ipv4.conf.all.send_redirects", "0"},
		{"net.ipv4.conf.all.accept_redirects", "0"},
		{"net.ipv4.conf.all.accept_source_route", "0"},
		{"kernel.randomize_va_space", "2"},
		{"net.ipv4.tcp_syncookies", "1"},
		{"fs.suid_dumpable", "0"},
	}

	var results []SysctlParamInfo
	for _, p := range params {
		value := readSysctlParam(p.name)
		info := SysctlParamInfo{
			Name:          p.name,
			Value:         value,
			ExpectedValue: p.expectedValue,
			IsSecure:      value == p.expectedValue,
		}
		logger.Debug("GetSysctlSecurityParams: 参数 %s 当前值=%s 期望值=%s 安全=%v", p.name, value, p.expectedValue, info.IsSecure)
		results = append(results, info)
	}

	logger.Debug("GetSysctlSecurityParams: 共检查 %d 个内核参数", len(results))
	return results
}

// readSysctlParam 读取单个sysctl参数，优先读/proc/sys/
func readSysctlParam(name string) string {
	path := "/proc/sys/" + strings.ReplaceAll(name, ".", "/")
	// #nosec G304 -- 采集系统信息需要动态路径
	data, err := os.ReadFile(path)
	if err != nil {
		logger.Debug("readSysctlParam: 读取sysctl参数失败 %s: %v", name, err)
		return ""
	}
	return parseSysctlContent(string(data))
}

// parseSysctlContent 解析sysctl文件内容，去除空白
func parseSysctlContent(content string) string {
	return strings.TrimSpace(content)
}
