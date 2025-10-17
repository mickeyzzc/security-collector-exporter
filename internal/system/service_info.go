package system

import (
	"fmt"
	"os"
	"path/filepath"
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
	// 使用map去重，确保每个服务名只出现一次
	serviceMap := make(map[string]ServiceInfo)

	// 1. 获取所有systemd服务
	systemdServices := getAllSystemdServices()
	for _, service := range systemdServices {
		serviceMap[service.Name] = service
	}

	// 2. 获取所有传统init服务
	initServices := getAllInitServices()
	for _, service := range initServices {
		// 如果systemd服务已存在，优先使用systemd服务信息
		if _, exists := serviceMap[service.Name]; !exists {
			serviceMap[service.Name] = service
		}
	}

	// 3. 获取X Window服务信息（特殊处理，覆盖同名服务）
	xwindowServices := getXWindowServices()
	for _, service := range xwindowServices {
		serviceMap[service.Name] = service
	}

	// 将map转换为slice
	var services []ServiceInfo
	for _, service := range serviceMap {
		services = append(services, service)
	}

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

// getAllSystemdServices 获取所有systemd服务信息
func getAllSystemdServices() []ServiceInfo {
	// 使用map去重，确保每个服务名只出现一次
	serviceMap := make(map[string]ServiceInfo)

	// 扫描systemd服务目录（按优先级顺序）
	systemdPaths := []string{
		"/etc/systemd/system",     // 最高优先级：用户自定义服务
		"/usr/lib/systemd/system", // 中等优先级：系统安装的服务
		"/lib/systemd/system",     // 最低优先级：基础系统服务
	}

	for _, systemdPath := range systemdPaths {
		entries, err := os.ReadDir(systemdPath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			name := entry.Name()
			// 只处理.service文件
			if !strings.HasSuffix(name, ".service") {
				continue
			}

			// 移除.service后缀
			serviceName := strings.TrimSuffix(name, ".service")

			// 如果服务已存在，跳过（保持高优先级目录的服务信息）
			if _, exists := serviceMap[serviceName]; exists {
				continue
			}

			serviceInfo := ServiceInfo{
				Name:        serviceName,
				IsRunning:   false,
				ServiceType: "systemd",
				IsEnabled:   false,
			}

			// 检查服务是否运行
			if isSystemdServiceRunning(serviceName) {
				serviceInfo.IsRunning = true
			}

			// 检查服务是否启用
			if isSystemdServiceEnabled(serviceName) {
				serviceInfo.IsEnabled = true
			}

			serviceMap[serviceName] = serviceInfo
		}
	}

	// 将map转换为slice
	var services []ServiceInfo
	for _, service := range serviceMap {
		services = append(services, service)
	}

	return services
}

// getAllInitServices 获取所有传统init服务信息
func getAllInitServices() []ServiceInfo {
	// 使用map去重，确保每个服务名只出现一次
	serviceMap := make(map[string]ServiceInfo)

	// 扫描init服务目录（按优先级顺序）
	initPaths := []string{
		"/etc/init.d",      // 最高优先级：用户自定义服务
		"/etc/rc.d/init.d", // 最低优先级：系统基础服务
	}

	for _, initPath := range initPaths {
		entries, err := os.ReadDir(initPath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			serviceName := entry.Name()

			// 如果服务已存在，跳过（保持高优先级目录的服务信息）
			if _, exists := serviceMap[serviceName]; exists {
				continue
			}

			serviceInfo := ServiceInfo{
				Name:        serviceName,
				IsRunning:   false,
				ServiceType: "init",
				IsEnabled:   false,
			}

			// 检查服务是否运行
			if isInitServiceRunning(serviceName) {
				serviceInfo.IsRunning = true
			}

			// 检查服务是否启用（通过运行级别链接）
			if isInitServiceEnabled(serviceName) {
				serviceInfo.IsEnabled = true
			}

			serviceMap[serviceName] = serviceInfo
		}
	}

	// 将map转换为slice
	var services []ServiceInfo
	for _, service := range serviceMap {
		services = append(services, service)
	}

	return services
}

// isInitServiceEnabled 检查传统init服务是否启用
func isInitServiceEnabled(serviceName string) bool {
	// 检查运行级别链接
	for _, level := range []string{"2", "3", "4", "5"} {
		rcPath := fmt.Sprintf("/etc/rc%s.d/S*%s", level, serviceName)
		matches, err := filepath.Glob(rcPath)
		if err == nil && len(matches) > 0 {
			return true
		}
	}
	return false
}

// isSystemdServiceRunning 检查systemd服务是否运行
func isSystemdServiceRunning(serviceName string) bool {
	// 1. 检查systemd服务状态文件
	serviceStatePath := fmt.Sprintf("/run/systemd/system/%s.service", serviceName)
	if _, err := os.Stat(serviceStatePath); err == nil {
		if content, err := os.ReadFile(serviceStatePath); err == nil {
			if strings.Contains(string(content), "ActiveState=active") {
				return true
			}
		}
	}

	// 2. 检查systemd服务状态文件（备用路径）
	serviceStatePath2 := fmt.Sprintf("/run/systemd/transient/%s.service", serviceName)
	if _, err := os.Stat(serviceStatePath2); err == nil {
		if content, err := os.ReadFile(serviceStatePath2); err == nil {
			if strings.Contains(string(content), "ActiveState=active") {
				return true
			}
		}
	}

	// 3. 从/proc中检查进程是否在运行
	return isProcessRunning(serviceName)
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
