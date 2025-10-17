package system

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ServiceInfo 服务信息结构
type ServiceInfo struct {
	Name        string // 服务名
	IsRunning   bool   // 是否运行
	ServiceType string // 服务类型: systemd, init, xwindow, wayland
	IsEnabled   bool   // 是否启用
}

// GetAllServicesInfo 获取所有服务信息
func GetAllServicesInfo() ([]ServiceInfo, error) {
	var services []ServiceInfo

	// 1. 获取X Window相关服务信息
	xwindowServices := getXWindowServices()
	services = append(services, xwindowServices...)

	// 2. 获取不必要服务信息
	unnecessaryServices := getUnnecessaryServices()
	services = append(services, unnecessaryServices...)

	// 3. 获取其他重要服务信息
	otherServices := getOtherImportantServices()
	services = append(services, otherServices...)

	return services, nil
}

// getXWindowServices 获取X Window相关服务信息
func getXWindowServices() []ServiceInfo {
	var services []ServiceInfo

	// 检查X Window是否启用
	xwindowEnabled := false
	serviceType := ""

	// 1. 检查systemd默认target
	defaultTargetPath := "/etc/systemd/system/default.target"
	if target, err := os.Readlink(defaultTargetPath); err == nil {
		if strings.Contains(target, "graphical.target") {
			xwindowEnabled = true
			serviceType = "systemd"
		}
	}

	// 2. 检查systemd配置文件
	if !xwindowEnabled {
		systemdConfigPath := "/etc/systemd/system.conf"
		if content, err := os.ReadFile(systemdConfigPath); err == nil {
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "DefaultTarget=") {
					if strings.Contains(line, "graphical.target") {
						xwindowEnabled = true
						serviceType = "systemd"
						break
					}
				}
			}
		}
	}

	// 3. 检查inittab文件
	if !xwindowEnabled {
		inittabPath := "/etc/inittab"
		if content, err := os.ReadFile(inittabPath); err == nil {
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "id:") && strings.Contains(line, ":initdefault:") {
					if strings.Contains(line, ":5:") {
						xwindowEnabled = true
						serviceType = "init"
						break
					}
				}
			}
		}
	}

	// 4. 检查X11相关文件
	if !xwindowEnabled {
		x11Paths := []string{
			"/usr/bin/X",
			"/usr/bin/Xorg",
			"/usr/bin/X11",
			"/usr/X11R6/bin/X",
			"/etc/X11",
		}

		for _, path := range x11Paths {
			if _, err := os.Stat(path); err == nil {
				xwindowEnabled = true
				serviceType = "x11"
				break
			}
		}
	}

	// 5. 检查显示管理器
	displayManagers := []string{
		"gdm", "lightdm", "sddm", "xdm", "kdm",
	}

	for _, dm := range displayManagers {
		dmPaths := []string{
			"/etc/systemd/system/display-manager.service",
			fmt.Sprintf("/lib/systemd/system/%s.service", dm),
			fmt.Sprintf("/usr/lib/systemd/system/%s.service", dm),
		}

		for _, dmPath := range dmPaths {
			if _, err := os.Stat(dmPath); err == nil {
				xwindowEnabled = true
				serviceType = "systemd"
				break
			}
		}
	}

	// 6. 检查Wayland
	waylandPaths := []string{
		"/usr/bin/wayland-session",
		"/usr/bin/gnome-session",
		"/usr/bin/kde-session",
	}

	for _, path := range waylandPaths {
		if _, err := os.Stat(path); err == nil {
			xwindowEnabled = true
			serviceType = "wayland"
			break
		}
	}

	// 添加X Window服务信息
	services = append(services, ServiceInfo{
		Name:        "xwindow",
		IsRunning:   xwindowEnabled,
		ServiceType: serviceType,
		IsEnabled:   xwindowEnabled,
	})

	return services
}

// getUnnecessaryServices 获取不必要服务信息
func getUnnecessaryServices() []ServiceInfo {
	var services []ServiceInfo

	unnecessaryServiceNames := []string{
		"nfs", "nfs-server", "cups", "bluetooth",
		"avahi-daemon", "rpcbind", "postfix",
	}

	for _, serviceName := range unnecessaryServiceNames {
		serviceInfo := ServiceInfo{
			Name:        serviceName,
			IsRunning:   false,
			ServiceType: "unknown",
			IsEnabled:   false,
		}

		// 检查systemd服务
		if isSystemdServiceRunning(serviceName) {
			serviceInfo.IsRunning = true
			serviceInfo.ServiceType = "systemd"
		}

		// 检查是否启用
		if isSystemdServiceEnabled(serviceName) {
			serviceInfo.IsEnabled = true
			if serviceInfo.ServiceType == "unknown" {
				serviceInfo.ServiceType = "systemd"
			}
		}

		// 检查传统init服务
		if isInitServiceRunning(serviceName) {
			serviceInfo.IsRunning = true
			serviceInfo.ServiceType = "init"
		}

		// 检查进程是否在运行
		if isServiceRunning(serviceName) {
			serviceInfo.IsRunning = true
			if serviceInfo.ServiceType == "unknown" {
				serviceInfo.ServiceType = "process"
			}
		}

		services = append(services, serviceInfo)
	}

	return services
}

// getOtherImportantServices 获取其他重要服务信息
func getOtherImportantServices() []ServiceInfo {
	var services []ServiceInfo

	importantServices := []string{
		"sshd", "firewalld", "iptables", "nftables",
		"selinux", "auditd", "rsyslog", "systemd-logind",
	}

	for _, serviceName := range importantServices {
		serviceInfo := ServiceInfo{
			Name:        serviceName,
			IsRunning:   false,
			ServiceType: "unknown",
			IsEnabled:   false,
		}

		// 检查systemd服务
		if isSystemdServiceRunning(serviceName) {
			serviceInfo.IsRunning = true
			serviceInfo.ServiceType = "systemd"
		}

		// 检查是否启用
		if isSystemdServiceEnabled(serviceName) {
			serviceInfo.IsEnabled = true
			if serviceInfo.ServiceType == "unknown" {
				serviceInfo.ServiceType = "systemd"
			}
		}

		// 检查进程是否在运行
		if isServiceRunning(serviceName) {
			serviceInfo.IsRunning = true
			if serviceInfo.ServiceType == "unknown" {
				serviceInfo.ServiceType = "process"
			}
		}

		services = append(services, serviceInfo)
	}

	return services
}

// isSystemdServiceRunning 检查systemd服务是否运行
func isSystemdServiceRunning(serviceName string) bool {
	// 检查systemd服务状态文件
	serviceStatePath := fmt.Sprintf("/run/systemd/system/%s.service", serviceName)
	if _, err := os.Stat(serviceStatePath); err == nil {
		if content, err := os.ReadFile(serviceStatePath); err == nil {
			return strings.Contains(string(content), "ActiveState=active")
		}
	}
	return false
}

// isSystemdServiceEnabled 检查systemd服务是否启用
func isSystemdServiceEnabled(serviceName string) bool {
	// 检查服务是否被启用（通过符号链接）
	enabledPaths := []string{
		fmt.Sprintf("/etc/systemd/system/multi-user.target.wants/%s.service", serviceName),
		fmt.Sprintf("/etc/systemd/system/graphical.target.wants/%s.service", serviceName),
		fmt.Sprintf("/etc/systemd/system/default.target.wants/%s.service", serviceName),
	}

	for _, enabledPath := range enabledPaths {
		if _, err := os.Stat(enabledPath); err == nil {
			return true
		}
	}
	return false
}

// isInitServiceRunning 检查传统init服务是否运行
func isInitServiceRunning(serviceName string) bool {
	// 检查传统init脚本
	initScriptPaths := []string{
		fmt.Sprintf("/etc/init.d/%s", serviceName),
		fmt.Sprintf("/etc/rc.d/init.d/%s", serviceName),
	}

	for _, initPath := range initScriptPaths {
		if _, err := os.Stat(initPath); err == nil {
			// 检查运行级别链接
			for _, level := range []string{"2", "3", "4", "5"} {
				rcPath := fmt.Sprintf("/etc/rc%s.d/S*%s", level, serviceName)
				matches, err := filepath.Glob(rcPath)
				if err == nil && len(matches) > 0 {
					return true
				}
			}
		}
	}
	return false
}

// isServiceRunning 检查服务进程是否在运行
func isServiceRunning(serviceName string) bool {
	// 读取/proc目录获取所有进程
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// 检查是否为数字目录（进程ID）
		pid := entry.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}

		// 读取进程命令行
		cmdlinePath := fmt.Sprintf("/proc/%s/cmdline", pid)
		if content, err := os.ReadFile(cmdlinePath); err == nil {
			cmdline := string(content)
			// 检查命令行是否包含服务名
			if strings.Contains(cmdline, serviceName) {
				return true
			}
		}
	}

	return false
}
