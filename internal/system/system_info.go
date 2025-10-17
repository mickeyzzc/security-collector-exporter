package system

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// PatchInfo 补丁信息结构
type PatchInfo struct {
	LastPatchTime string // 最后一次补丁时间
	PackageCount  int    // 已安装包数量
	PackageType   string // 包管理器类型: rpm, dpkg, unknown
}

// GetPatchInfo 获取补丁信息
func GetPatchInfo() (*PatchInfo, error) {
	info := &PatchInfo{
		LastPatchTime: "unknown",
		PackageCount:  0,
		PackageType:   "unknown",
	}

	// 1. 检查RedHat系系统（RPM包管理器）
	if _, err := os.Stat("/etc/redhat-release"); err == nil {
		info.PackageType = "rpm"

		// 检查RPM数据库目录
		rpmDbPaths := []string{
			"/var/lib/rpm/Packages",
			"/var/lib/rpm/Name",
			"/var/lib/rpm/Group",
		}

		var latestTime time.Time
		packageCount := 0

		for _, dbPath := range rpmDbPaths {
			if stat, err := os.Stat(dbPath); err == nil {
				packageCount++
				if stat.ModTime().After(latestTime) {
					latestTime = stat.ModTime()
				}
			}
		}

		// 检查RPM日志文件
		rpmLogPaths := []string{
			"/var/log/rpm.log",
			"/var/log/yum.log",
			"/var/log/dnf.log",
		}

		for _, logPath := range rpmLogPaths {
			if stat, err := os.Stat(logPath); err == nil {
				if stat.ModTime().After(latestTime) {
					latestTime = stat.ModTime()
				}
			}
		}

		if !latestTime.IsZero() {
			info.LastPatchTime = latestTime.Format("2006-01-02 15:04:05")
		}
		info.PackageCount = packageCount
		return info, nil
	}

	// 2. 检查Debian/Ubuntu系系统（DPKG包管理器）
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		info.PackageType = "dpkg"

		// 检查DPKG状态文件
		dpkgStatusPath := "/var/lib/dpkg/status"
		if stat, err := os.Stat(dpkgStatusPath); err == nil {
			info.LastPatchTime = stat.ModTime().Format("2006-01-02 15:04:05")
		}

		// 统计已安装包数量
		if content, err := os.ReadFile(dpkgStatusPath); err == nil {
			packageCount := strings.Count(string(content), "Package:")
			info.PackageCount = packageCount
		}

		// 检查APT日志文件
		aptLogPaths := []string{
			"/var/log/apt/history.log",
			"/var/log/apt/term.log",
			"/var/log/dpkg.log",
		}

		var latestTime time.Time
		for _, logPath := range aptLogPaths {
			if stat, err := os.Stat(logPath); err == nil {
				if stat.ModTime().After(latestTime) {
					latestTime = stat.ModTime()
				}
			}
		}

		if !latestTime.IsZero() {
			info.LastPatchTime = latestTime.Format("2006-01-02 15:04:05")
		}

		return info, nil
	}

	// 3. 检查其他包管理器
	// 检查Pacman (Arch Linux)
	if _, err := os.Stat("/var/lib/pacman"); err == nil {
		info.PackageType = "pacman"

		// 检查Pacman数据库
		pacmanDbPath := "/var/lib/pacman/local"
		if stat, err := os.Stat(pacmanDbPath); err == nil {
			info.LastPatchTime = stat.ModTime().Format("2006-01-02 15:04:05")
		}

		// 统计包数量
		if entries, err := os.ReadDir(pacmanDbPath); err == nil {
			info.PackageCount = len(entries)
		}

		return info, nil
	}

	// 4. 检查系统更新目录
	updatePaths := []string{
		"/var/log/updates",
		"/var/log/upgrade",
		"/var/log/system-update",
	}

	var latestTime time.Time
	for _, updatePath := range updatePaths {
		if stat, err := os.Stat(updatePath); err == nil {
			if stat.ModTime().After(latestTime) {
				latestTime = stat.ModTime()
			}
		}
	}

	if !latestTime.IsZero() {
		info.LastPatchTime = latestTime.Format("2006-01-02 15:04:05")
		info.PackageType = "system"
	}

	return info, nil
}

// SystemTargetInfo 系统目标信息结构
type SystemTargetInfo struct {
	CurrentTarget string // 当前默认目标
	TargetType    string // 目标类型: systemd, init, unknown
}

// GetSystemTargetInfo 获取系统目标信息
func GetSystemTargetInfo() (*SystemTargetInfo, error) {
	info := &SystemTargetInfo{
		CurrentTarget: "unknown",
		TargetType:    "unknown",
	}

	// 1. 检查systemd默认target（通过符号链接）
	defaultTargetPath := "/etc/systemd/system/default.target"
	if target, err := os.Readlink(defaultTargetPath); err == nil {
		// 解析符号链接路径，获取实际的目标名
		if strings.Contains(target, "multi-user.target") {
			info.CurrentTarget = "multi-user.target"
			info.TargetType = "systemd"
		} else if strings.Contains(target, "graphical.target") {
			info.CurrentTarget = "graphical.target"
			info.TargetType = "systemd"
		} else {
			info.CurrentTarget = target
			info.TargetType = "systemd"
		}
		return info, nil
	}

	// 2. 检查systemd配置文件
	systemdConfigPath := "/etc/systemd/system.conf"
	if content, err := os.ReadFile(systemdConfigPath); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "DefaultTarget=") {
				target := strings.TrimSpace(strings.TrimPrefix(line, "DefaultTarget="))
				if target == "multi-user.target" {
					info.CurrentTarget = "multi-user.target"
					info.TargetType = "systemd"
				} else if target == "graphical.target" {
					info.CurrentTarget = "graphical.target"
					info.TargetType = "systemd"
				} else {
					info.CurrentTarget = target
					info.TargetType = "systemd"
				}
				return info, nil
			}
		}
	}

	// 3. 检查传统init系统（inittab）
	inittabPath := "/etc/inittab"
	if content, err := os.ReadFile(inittabPath); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "id:") && strings.Contains(line, ":initdefault:") {
				// 解析运行级别
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					runlevel := parts[1]
					switch runlevel {
					case "3":
						info.CurrentTarget = "runlevel-3"
						info.TargetType = "init"
					case "5":
						info.CurrentTarget = "runlevel-5"
						info.TargetType = "init"
					default:
						info.CurrentTarget = "runlevel-" + runlevel
						info.TargetType = "init"
					}
					return info, nil
				}
			}
		}
	}

	// 4. 检查systemd运行级别映射
	runlevelMappings := map[string]string{
		"runlevel0.target": "poweroff.target",
		"runlevel1.target": "rescue.target",
		"runlevel2.target": "multi-user.target",
		"runlevel3.target": "multi-user.target",
		"runlevel4.target": "multi-user.target",
		"runlevel5.target": "graphical.target",
		"runlevel6.target": "reboot.target",
	}

	for runlevelTarget := range runlevelMappings {
		targetPath := fmt.Sprintf("/etc/systemd/system/%s", runlevelTarget)
		if _, err := os.Stat(targetPath); err == nil {
			info.CurrentTarget = runlevelTarget
			info.TargetType = "systemd-runlevel"
			return info, nil
		}
	}

	// 5. 检查当前运行的目标（通过/proc/1/comm）
	if content, err := os.ReadFile("/proc/1/comm"); err == nil {
		initProcess := strings.TrimSpace(string(content))
		if initProcess == "systemd" {
			info.TargetType = "systemd"
			info.CurrentTarget = "unknown-systemd"
		} else {
			info.TargetType = "init"
			info.CurrentTarget = "unknown-init"
		}
	}

	return info, nil
}
