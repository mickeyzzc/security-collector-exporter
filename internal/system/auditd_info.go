package system

import (
	"os"
	"os/exec"
	"path/filepath"
	"security-exporter/pkg/logger"
	"strings"
)

// AuditdInfo auditd审计服务信息
type AuditdInfo struct {
	IsRunning      bool   // 是否运行
	RulesCount     int    // 规则数量
	ServiceEnabled bool   // 服务是否启用
	Version        string // 版本
}

// GetAuditdInfo 获取auditd审计服务状态
func GetAuditdInfo() AuditdInfo {
	logger.Debug("GetAuditdInfo: 开始获取auditd审计服务信息")

	info := AuditdInfo{}

	info.IsRunning = isProcessRunning("auditd")
	logger.Debug("GetAuditdInfo: auditd运行状态: %v", info.IsRunning)

	info.ServiceEnabled = isAuditdServiceEnabled()
	logger.Debug("GetAuditdInfo: auditd服务启用状态: %v", info.ServiceEnabled)

	info.Version = getAuditdVersion()
	logger.Debug("GetAuditdInfo: auditd版本: %s", info.Version)

	info.RulesCount = countAuditRules()
	logger.Debug("GetAuditdInfo: audit规则数量: %d", info.RulesCount)

	return info
}

// countAuditRules 统计audit规则数
func countAuditRules() int {
	out, err := exec.Command("auditctl", "-l").Output()
	if err == nil {
		return countAuditRulesFromAuditctlOutput(string(out))
	}
	logger.Debug("countAuditRules: auditctl命令执行失败: %v", err)

	rulesPaths := []string{
		"/etc/audit/audit.rules",
		"/etc/audit/rules.d/audit.rules",
	}

	for _, path := range rulesPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		count := countAuditRulesFromContent(string(data))
		logger.Debug("countAuditRules: 从 %s 读取到 %d 条规则", path, count)
		return count
	}

	logger.Debug("countAuditRules: 未找到audit规则文件")
	return 0
}

// countAuditRulesFromAuditctlOutput 从auditctl输出统计规则数
func countAuditRulesFromAuditctlOutput(output string) int {
	count := 0
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "No rules") {
			count++
		}
	}
	return count
}

// countAuditRulesFromContent 从规则文件内容统计规则数（跳过注释和空行）
func countAuditRulesFromContent(content string) int {
	count := 0
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return count
}

// getAuditdVersion 获取auditd版本
func getAuditdVersion() string {
	// 尝试 auditctl -v
	out, err := exec.Command("auditctl", "-v").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}

	// 尝试 auditd -v
	out, err = exec.Command("auditd", "-v").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}

	logger.Debug("getAuditdVersion: 无法获取auditd版本: %v", err)
	return ""
}

// isAuditdServiceEnabled 检查auditd服务是否启用
func isAuditdServiceEnabled() bool {
	// 尝试 systemctl is-enabled
	out, err := exec.Command("systemctl", "is-enabled", "auditd").Output()
	if err == nil {
		status := strings.TrimSpace(string(out))
		return status == "enabled"
	}

	// 回退到检查init脚本符号链接
	initPaths := []string{
		"/etc/rc3.d/S*auditd",
		"/etc/rc3.d/S*auditd",
		"/etc/rc5.d/S*auditd",
	}
	for _, pattern := range initPaths {
		matches, _ := filepath.Glob(pattern)
		if len(matches) > 0 {
			return true
		}
	}

	logger.Debug("isAuditdServiceEnabled: 无法确定auditd启用状态")
	return false
}
