package system

import (
	"fmt"
	"os"
	"security-exporter/pkg/logger"
	"strings"
	"time"
)

// PatchTimeInfo 补丁时间信息结构
type PatchTimeInfo struct {
	LastPatchTime string // 最后一次补丁时间
	PackageType   string // 包管理器类型: rpm, dpkg, unknown
}

// PackageCountInfo 包数量信息结构
type PackageCountInfo struct {
	PackageCount int    // 已安装包数量
	PackageType  string // 包管理器类型: rpm, dpkg, unknown
}

// GetPatchTimeInfo 获取补丁时间信息
func GetPatchTimeInfo() (*PatchTimeInfo, error) {
	logger.Debug("GetPatchTimeInfo: 开始获取补丁时间信息")

	info := &PatchTimeInfo{
		LastPatchTime: "unknown",
		PackageType:   "unknown",
	}

	// 1. 检查RedHat系系统（RPM包管理器）
	logger.Debug("GetPatchTimeInfo: 检查 RedHat 系统 /etc/redhat-release")
	if _, err := os.Stat("/etc/redhat-release"); err == nil {
		logger.Debug("GetPatchTimeInfo: 检测到 RedHat 系统，使用 RPM 包管理器")
		info.PackageType = "rpm"

		// 检查RPM数据库目录
		rpmDbPaths := []string{
			"/var/lib/rpm/Packages",
			"/var/lib/rpm/Name",
			"/var/lib/rpm/Group",
		}

		var latestTime time.Time

		for _, dbPath := range rpmDbPaths {
			logger.Debug("GetPatchTimeInfo: 检查 RPM 数据库文件 %s", dbPath)
			if stat, err := os.Stat(dbPath); err == nil {
				logger.Debug("GetPatchTimeInfo: RPM 数据库文件存在，修改时间: %s", stat.ModTime().Format("2006-01-02 15:04:05"))
				if stat.ModTime().After(latestTime) {
					latestTime = stat.ModTime()
				}
			} else {
				logger.Debug("GetPatchTimeInfo: RPM 数据库文件不存在: %v", err)
			}
		}

		// 检查RPM日志文件
		rpmLogPaths := []string{
			"/var/log/rpm.log",
			"/var/log/yum.log",
			"/var/log/dnf.log",
		}

		for _, logPath := range rpmLogPaths {
			logger.Debug("GetPatchTimeInfo: 检查 RPM 日志文件 %s", logPath)
			if stat, err := os.Stat(logPath); err == nil {
				logger.Debug("GetPatchTimeInfo: RPM 日志文件存在，修改时间: %s", stat.ModTime().Format("2006-01-02 15:04:05"))
				if stat.ModTime().After(latestTime) {
					latestTime = stat.ModTime()
				}
			} else {
				logger.Debug("GetPatchTimeInfo: RPM 日志文件不存在: %v", err)
			}
		}

		if !latestTime.IsZero() {
			info.LastPatchTime = latestTime.Format("2006-01-02 15:04:05")
			logger.Debug("GetPatchTimeInfo: RPM 系统最后补丁时间: %s", info.LastPatchTime)
		} else {
			logger.Debug("GetPatchTimeInfo: RPM 系统未找到有效的补丁时间")
		}
		return info, nil
	}
	logger.Debug("GetPatchTimeInfo: 非 RedHat 系统")

	// 2. 检查Debian/Ubuntu系系统（DPKG包管理器）
	logger.Debug("GetPatchTimeInfo: 检查 Debian/Ubuntu 系统 /etc/debian_version")
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		logger.Debug("GetPatchTimeInfo: 检测到 Debian/Ubuntu 系统，使用 DPKG 包管理器")
		info.PackageType = "dpkg"

		// 检查DPKG状态文件
		dpkgStatusPath := "/var/lib/dpkg/status"
		logger.Debug("GetPatchTimeInfo: 检查 DPKG 状态文件 %s", dpkgStatusPath)
		if stat, err := os.Stat(dpkgStatusPath); err == nil {
			info.LastPatchTime = stat.ModTime().Format("2006-01-02 15:04:05")
			logger.Debug("GetPatchTimeInfo: DPKG 状态文件存在，修改时间: %s", info.LastPatchTime)
		} else {
			logger.Debug("GetPatchTimeInfo: DPKG 状态文件不存在: %v", err)
		}

		// 检查APT日志文件
		aptLogPaths := []string{
			"/var/log/apt/history.log",
			"/var/log/apt/term.log",
			"/var/log/dpkg.log",
		}

		var latestTime time.Time
		for _, logPath := range aptLogPaths {
			logger.Debug("GetPatchTimeInfo: 检查 APT 日志文件 %s", logPath)
			if stat, err := os.Stat(logPath); err == nil {
				logger.Debug("GetPatchTimeInfo: APT 日志文件存在，修改时间: %s", stat.ModTime().Format("2006-01-02 15:04:05"))
				if stat.ModTime().After(latestTime) {
					latestTime = stat.ModTime()
				}
			} else {
				logger.Debug("GetPatchTimeInfo: APT 日志文件不存在: %v", err)
			}
		}

		if !latestTime.IsZero() {
			info.LastPatchTime = latestTime.Format("2006-01-02 15:04:05")
			logger.Debug("GetPatchTimeInfo: DPKG 系统最后补丁时间: %s", info.LastPatchTime)
		} else {
			logger.Debug("GetPatchTimeInfo: DPKG 系统使用状态文件时间")
		}

		return info, nil
	}
	logger.Debug("GetPatchTimeInfo: 非 Debian/Ubuntu 系统")

	// 3. 检查其他包管理器
	// 检查Pacman (Arch Linux)
	logger.Debug("GetPatchTimeInfo: 检查 Arch Linux 系统 /var/lib/pacman")
	if _, err := os.Stat("/var/lib/pacman"); err == nil {
		logger.Debug("GetPatchTimeInfo: 检测到 Arch Linux 系统，使用 Pacman 包管理器")
		info.PackageType = "pacman"

		// 检查Pacman数据库
		pacmanDbPath := "/var/lib/pacman/local"
		logger.Debug("GetPatchTimeInfo: 检查 Pacman 数据库 %s", pacmanDbPath)
		if stat, err := os.Stat(pacmanDbPath); err == nil {
			info.LastPatchTime = stat.ModTime().Format("2006-01-02 15:04:05")
			logger.Debug("GetPatchTimeInfo: Pacman 数据库存在，修改时间: %s", info.LastPatchTime)
		} else {
			logger.Debug("GetPatchTimeInfo: Pacman 数据库不存在: %v", err)
		}

		return info, nil
	}
	logger.Debug("GetPatchTimeInfo: 非 Arch Linux 系统")

	// 4. 检查系统更新目录
	logger.Debug("GetPatchTimeInfo: 检查通用系统更新目录")
	updatePaths := []string{
		"/var/log/updates",
		"/var/log/upgrade",
		"/var/log/system-update",
	}

	var latestTime time.Time
	for _, updatePath := range updatePaths {
		logger.Debug("GetPatchTimeInfo: 检查更新目录 %s", updatePath)
		if stat, err := os.Stat(updatePath); err == nil {
			logger.Debug("GetPatchTimeInfo: 更新目录存在，修改时间: %s", stat.ModTime().Format("2006-01-02 15:04:05"))
			if stat.ModTime().After(latestTime) {
				latestTime = stat.ModTime()
			}
		} else {
			logger.Debug("GetPatchTimeInfo: 更新目录不存在: %v", err)
		}
	}

	if !latestTime.IsZero() {
		info.LastPatchTime = latestTime.Format("2006-01-02 15:04:05")
		info.PackageType = "system"
		logger.Debug("GetPatchTimeInfo: 通用系统最后补丁时间: %s", info.LastPatchTime)
	} else {
		logger.Debug("GetPatchTimeInfo: 未找到任何补丁时间信息")
	}

	return info, nil
}

// GetPackageCountInfo 获取包数量信息
func GetPackageCountInfo() (*PackageCountInfo, error) {
	logger.Debug("GetPackageCountInfo: 开始获取包数量信息")

	info := &PackageCountInfo{
		PackageCount: 0,
		PackageType:  "unknown",
	}

	// 1. 检查RedHat系系统（RPM包管理器）
	logger.Debug("GetPackageCountInfo: 检查 RedHat 系统 /etc/redhat-release")
	if _, err := os.Stat("/etc/redhat-release"); err == nil {
		logger.Debug("GetPackageCountInfo: 检测到 RedHat 系统，使用 RPM 包管理器")
		info.PackageType = "rpm"

		// 检查RPM数据库目录
		rpmDbPaths := []string{
			"/var/lib/rpm/Packages",
			"/var/lib/rpm/Name",
			"/var/lib/rpm/Group",
		}

		packageCount := 0
		for _, dbPath := range rpmDbPaths {
			logger.Debug("GetPackageCountInfo: 检查 RPM 数据库文件 %s", dbPath)
			if _, err := os.Stat(dbPath); err == nil {
				packageCount++
				logger.Debug("GetPackageCountInfo: RPM 数据库文件存在")
			} else {
				logger.Debug("GetPackageCountInfo: RPM 数据库文件不存在: %v", err)
			}
		}

		info.PackageCount = packageCount
		logger.Debug("GetPackageCountInfo: RPM 系统包数量: %d", packageCount)
		return info, nil
	}
	logger.Debug("GetPackageCountInfo: 非 RedHat 系统")

	// 2. 检查Debian/Ubuntu系系统（DPKG包管理器）
	logger.Debug("GetPackageCountInfo: 检查 Debian/Ubuntu 系统 /etc/debian_version")
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		logger.Debug("GetPackageCountInfo: 检测到 Debian/Ubuntu 系统，使用 DPKG 包管理器")
		info.PackageType = "dpkg"

		// 统计已安装包数量
		dpkgStatusPath := "/var/lib/dpkg/status"
		logger.Debug("GetPackageCountInfo: 读取 DPKG 状态文件 %s", dpkgStatusPath)
		if content, err := os.ReadFile(dpkgStatusPath); err == nil {
			packageCount := strings.Count(string(content), "Package:")
			info.PackageCount = packageCount
			logger.Debug("GetPackageCountInfo: DPKG 系统包数量: %d", packageCount)
		} else {
			logger.Debug("GetPackageCountInfo: 无法读取 DPKG 状态文件: %v", err)
		}

		return info, nil
	}
	logger.Debug("GetPackageCountInfo: 非 Debian/Ubuntu 系统")

	// 3. 检查Pacman (Arch Linux)
	logger.Debug("GetPackageCountInfo: 检查 Arch Linux 系统 /var/lib/pacman")
	if _, err := os.Stat("/var/lib/pacman"); err == nil {
		logger.Debug("GetPackageCountInfo: 检测到 Arch Linux 系统，使用 Pacman 包管理器")
		info.PackageType = "pacman"

		// 统计包数量
		pacmanDbPath := "/var/lib/pacman/local"
		logger.Debug("GetPackageCountInfo: 读取 Pacman 数据库目录 %s", pacmanDbPath)
		if entries, err := os.ReadDir(pacmanDbPath); err == nil {
			info.PackageCount = len(entries)
			logger.Debug("GetPackageCountInfo: Pacman 系统包数量: %d", len(entries))
		} else {
			logger.Debug("GetPackageCountInfo: 无法读取 Pacman 数据库目录: %v", err)
		}

		return info, nil
	}
	logger.Debug("GetPackageCountInfo: 非 Arch Linux 系统")

	logger.Debug("GetPackageCountInfo: 未找到任何包管理器，包数量为 0")
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
