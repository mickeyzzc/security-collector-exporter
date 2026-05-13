package system

import (
	"os"
	"os/exec"
	"security-exporter/pkg/logger"
	"strconv"
	"strings"
)

// SELinuxDetailInfo SELinux/AppArmor详细状态
type SELinuxDetailInfo struct {
	SELinuxMode      string // enforcing/permissive/disabled
	SELinuxPolicy    string // targeted/mls/minimum
	AppArmorEnabled  bool   // AppArmor是否启用
	AppArmorProfiles int    // AppArmor配置文件数
	AppArmorEnforced int    // AppArmor强制模式数
}

// GetSELinuxDetailInfo 获取SELinux/AppArmor运行时详细状态
func GetSELinuxDetailInfo() SELinuxDetailInfo {
	logger.Debug("GetSELinuxDetailInfo: 开始获取SELinux/AppArmor详细状态")

	info := SELinuxDetailInfo{}
	info.SELinuxMode = getSELinuxMode()
	logger.Debug("GetSELinuxDetailInfo: SELinux模式: %s", info.SELinuxMode)

	info.SELinuxPolicy = getSELinuxPolicy()
	logger.Debug("GetSELinuxDetailInfo: SELinux策略: %s", info.SELinuxPolicy)

	info.AppArmorEnabled = isAppArmorEnabled()
	logger.Debug("GetSELinuxDetailInfo: AppArmor启用: %v", info.AppArmorEnabled)

	if info.AppArmorEnabled {
		info.AppArmorProfiles, info.AppArmorEnforced = getAppArmorStats()
	}
	logger.Debug("GetSELinuxDetailInfo: AppArmor配置文件数=%d 强制模式数=%d", info.AppArmorProfiles, info.AppArmorEnforced)

	return info
}

// getSELinuxMode 获取SELinux运行模式
func getSELinuxMode() string {
	data, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err == nil {
		val := parseSELinuxModeFromContent(string(data))
		if val != "" {
			return val
		}
	}

	if _, err := os.Stat("/sys/fs/selinux"); os.IsNotExist(err) {
		out, err := exec.Command("getenforce").Output()
		if err == nil {
			return strings.ToLower(strings.TrimSpace(string(out)))
		}
		return "disabled"
	}

	out, err := exec.Command("getenforce").Output()
	if err == nil {
		return strings.ToLower(strings.TrimSpace(string(out)))
	}

	logger.Debug("getSELinuxMode: 无法获取SELinux模式: %v", err)
	return "unknown"
}

// parseSELinuxModeFromContent 从enforce文件内容解析SELinux模式
func parseSELinuxModeFromContent(content string) string {
	val := strings.TrimSpace(content)
	switch val {
	case "1":
		return "enforcing"
	case "0":
		return "permissive"
	}
	return ""
}

// parseSELinuxModeFromConfig 从配置文件内容解析SELINUX=行
func parseSELinuxModeFromConfig(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SELINUX=") {
			return strings.TrimPrefix(line, "SELINUX=")
		}
	}
	return ""
}

// getSELinuxPolicy 获取SELinux策略类型
func getSELinuxPolicy() string {
	data, err := os.ReadFile("/etc/selinux/config")
	if err == nil {
		policy := parseSELinuxPolicyFromConfig(string(data))
		if policy != "" {
			return policy
		}
	}

	out, err := exec.Command("sestatus").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "Loaded policy name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
	}

	logger.Debug("getSELinuxPolicy: 无法获取SELinux策略类型")
	return ""
}

// parseSELinuxPolicyFromConfig 从配置文件内容解析SELINUXTYPE=行
func parseSELinuxPolicyFromConfig(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SELINUXTYPE=") {
			return strings.TrimPrefix(line, "SELINUXTYPE=")
		}
	}
	return ""
}

// isAppArmorEnabled 检查AppArmor是否启用
func isAppArmorEnabled() bool {
	if _, err := os.Stat("/sys/kernel/security/apparmor"); err == nil {
		return true
	}

	out, err := exec.Command("aa-status", "--enabled").CombinedOutput()
	if err == nil {
		return true
	}
	if strings.TrimSpace(string(out)) == "" && err != nil {
		return false
	}

	logger.Debug("isAppArmorEnabled: AppArmor未启用")
	return false
}

// getAppArmorStats 获取AppArmor统计信息
func getAppArmorStats() (profiles int, enforced int) {
	out, err := exec.Command("aa-status", "--summary").Output()
	if err != nil {
		logger.Debug("getAppArmorStats: aa-status命令执行失败: %v", err)
		return 0, 0
	}

	return parseAppArmorStatsFromOutput(string(out))
}

// parseAppArmorStatsFromOutput 从aa-status输出解析AppArmor统计
func parseAppArmorStatsFromOutput(output string) (profiles int, enforced int) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "profiles are loaded") {
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				if n, err := strconv.Atoi(parts[0]); err == nil {
					profiles = n
				}
			}
		}
		if strings.Contains(line, "profiles are in enforce mode") {
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				if n, err := strconv.Atoi(parts[0]); err == nil {
					enforced = n
				}
			}
		}
	}
	return profiles, enforced
}
