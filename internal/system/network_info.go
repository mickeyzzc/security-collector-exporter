package system

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"security-exporter/pkg/logger"
)

// FirewallInfo 防火墙信息结构
type FirewallInfo struct {
	Enabled   bool   // 是否启用
	Type      string // 防火墙类型
	IsRunning bool   // 是否正在运行
}

// CheckFirewallStatus 检查防火墙状态
func CheckFirewallStatus() (FirewallInfo, error) {
	logger.Debug("CheckFirewallStatus: 开始检查防火墙状态")

	// 1. 检查firewalld服务状态
	logger.Debug("CheckFirewallStatus: 检查 firewalld")
	if isFirewalldActive() {
		logger.Debug("CheckFirewallStatus: 检测到 firewalld 已启用")
		isRunning := isProcessRunning("firewalld")
		logger.Debug("CheckFirewallStatus: firewalld 进程运行状态: %t", isRunning)
		return FirewallInfo{Enabled: true, Type: "firewalld", IsRunning: isRunning}, nil
	}
	logger.Debug("CheckFirewallStatus: firewalld 未启用")

	// 2. 检查ufw服务状态 (Ubuntu)
	logger.Debug("CheckFirewallStatus: 检查 ufw")
	if isUfwActive() {
		logger.Debug("CheckFirewallStatus: 检测到 ufw 已启用")
		isRunning := isProcessRunning("ufw")
		logger.Debug("CheckFirewallStatus: ufw 进程运行状态: %t", isRunning)
		return FirewallInfo{Enabled: true, Type: "ufw", IsRunning: isRunning}, nil
	}
	logger.Debug("CheckFirewallStatus: ufw 未启用")

	// 3. 检查iptables服务状态
	logger.Debug("CheckFirewallStatus: 检查 iptables 服务")
	if isIptablesActive() {
		logger.Debug("CheckFirewallStatus: 检测到 iptables 服务已启用")
		isRunning := isProcessRunning("iptables")
		logger.Debug("CheckFirewallStatus: iptables 进程运行状态: %t", isRunning)
		return FirewallInfo{Enabled: true, Type: "iptables", IsRunning: isRunning}, nil
	}
	logger.Debug("CheckFirewallStatus: iptables 服务未启用")

	// 4. 检查iptables规则文件
	logger.Debug("CheckFirewallStatus: 检查 iptables 规则文件")
	if hasIptablesRules() {
		logger.Debug("CheckFirewallStatus: 检测到 iptables 规则文件")
		// 有规则文件，检查进程是否运行
		isRunning := isProcessRunning("iptables")
		logger.Debug("CheckFirewallStatus: iptables 进程运行状态: %t", isRunning)
		return FirewallInfo{Enabled: true, Type: "iptables", IsRunning: isRunning}, nil
	}
	logger.Debug("CheckFirewallStatus: iptables 规则文件不存在")

	// 5. 检查nftables
	logger.Debug("CheckFirewallStatus: 检查 nftables")
	if isNftablesActive() {
		logger.Debug("CheckFirewallStatus: 检测到 nftables 已启用")
		isRunning := isProcessRunning("nftables")
		logger.Debug("CheckFirewallStatus: nftables 进程运行状态: %t", isRunning)
		return FirewallInfo{Enabled: true, Type: "nftables", IsRunning: isRunning}, nil
	}
	logger.Debug("CheckFirewallStatus: nftables 未启用")

	logger.Debug("CheckFirewallStatus: 未检测到任何防火墙")
	return FirewallInfo{Enabled: false, Type: "none", IsRunning: false}, nil
}

// isFirewalldActive 检查firewalld是否激活
func isFirewalldActive() bool {
	logger.Debug("isFirewalldActive: 开始检查 firewalld")

	// 检查systemd服务状态文件
	serviceStatePath := "/run/systemd/system/firewalld.service"
	logger.Debug("isFirewalldActive: 检查服务状态文件 %s", serviceStatePath)
	if _, err := os.Stat(serviceStatePath); err == nil {
		logger.Debug("isFirewalldActive: 服务状态文件存在")
		if content, err := os.ReadFile(serviceStatePath); err == nil {
			isActive := strings.Contains(string(content), "ActiveState=active")
			logger.Debug("isFirewalldActive: 服务状态文件包含 ActiveState=active: %t", isActive)
			return isActive
		} else {
			logger.Debug("isFirewalldActive: 无法读取服务状态文件: %v", err)
		}
	} else {
		logger.Debug("isFirewalldActive: 服务状态文件不存在: %v", err)
	}

	// 检查firewalld进程
	logger.Debug("isFirewalldActive: 检查 firewalld 进程")
	isRunning := isProcessRunning("firewalld")
	logger.Debug("isFirewalldActive: firewalld 进程运行状态: %t", isRunning)
	return isRunning
}

// isUfwActive 检查ufw是否激活
func isUfwActive() bool {
	logger.Debug("isUfwActive: 开始检查 ufw")

	// 检查systemd服务状态文件
	serviceStatePath := "/run/systemd/system/ufw.service"
	logger.Debug("isUfwActive: 检查服务状态文件 %s", serviceStatePath)
	if _, err := os.Stat(serviceStatePath); err == nil {
		logger.Debug("isUfwActive: 服务状态文件存在")
		if content, err := os.ReadFile(serviceStatePath); err == nil {
			isActive := strings.Contains(string(content), "ActiveState=active")
			logger.Debug("isUfwActive: 服务状态文件包含 ActiveState=active: %t", isActive)
			return isActive
		} else {
			logger.Debug("isUfwActive: 无法读取服务状态文件: %v", err)
		}
	} else {
		logger.Debug("isUfwActive: 服务状态文件不存在: %v", err)
	}

	// 检查ufw状态文件
	// 先检查/var/lib/ufw目录是否存在
	ufwDir := "/var/lib/ufw"
	logger.Debug("isUfwActive: 检查 ufw 目录 %s", ufwDir)
	if _, err := os.Stat(ufwDir); os.IsNotExist(err) {
		// 如果目录不存在，直接跳过文件状态检查
		logger.Debug("isUfwActive: ufw 目录不存在")
	} else {
		logger.Debug("isUfwActive: ufw 目录存在，检查状态文件")
		ufwStatusPath := "/var/lib/ufw/ufw-not-booted"
		if _, err := os.Stat(ufwStatusPath); os.IsNotExist(err) {
			// 如果状态文件不存在，说明ufw可能已启动
			logger.Debug("isUfwActive: ufw-not-booted 文件不存在，说明 ufw 可能已启动")
			return true
		} else {
			logger.Debug("isUfwActive: ufw-not-booted 文件存在，说明 ufw 未启动")
		}
	}

	// 检查ufw进程
	logger.Debug("isUfwActive: 检查 ufw 进程")
	isRunning := isProcessRunning("ufw")
	logger.Debug("isUfwActive: ufw 进程运行状态: %t", isRunning)
	return isRunning
}

// isIptablesActive 检查iptables服务是否激活
func isIptablesActive() bool {
	logger.Debug("isIptablesActive: 开始检查 iptables 服务")

	// 检查systemd服务状态文件
	serviceStatePath := "/run/systemd/system/iptables.service"
	logger.Debug("isIptablesActive: 检查服务状态文件 %s", serviceStatePath)
	if _, err := os.Stat(serviceStatePath); err == nil {
		logger.Debug("isIptablesActive: 服务状态文件存在")
		if content, err := os.ReadFile(serviceStatePath); err == nil {
			isActive := strings.Contains(string(content), "ActiveState=active")
			logger.Debug("isIptablesActive: 服务状态文件包含 ActiveState=active: %t", isActive)
			return isActive
		} else {
			logger.Debug("isIptablesActive: 无法读取服务状态文件: %v", err)
		}
	} else {
		logger.Debug("isIptablesActive: 服务状态文件不存在: %v", err)
	}

	// 检查iptables进程
	logger.Debug("isIptablesActive: 检查 iptables 进程")
	isRunning := isProcessRunning("iptables")
	logger.Debug("isIptablesActive: iptables 进程运行状态: %t", isRunning)
	return isRunning
}

// isNftablesActive 检查nftables是否激活
func isNftablesActive() bool {
	logger.Debug("isNftablesActive: 开始检查 nftables")

	// 检查systemd服务状态文件
	serviceStatePath := "/run/systemd/system/nftables.service"
	logger.Debug("isNftablesActive: 检查服务状态文件 %s", serviceStatePath)
	if _, err := os.Stat(serviceStatePath); err == nil {
		logger.Debug("isNftablesActive: 服务状态文件存在")
		if content, err := os.ReadFile(serviceStatePath); err == nil {
			isActive := strings.Contains(string(content), "ActiveState=active")
			logger.Debug("isNftablesActive: 服务状态文件包含 ActiveState=active: %t", isActive)
			return isActive
		} else {
			logger.Debug("isNftablesActive: 无法读取服务状态文件: %v", err)
		}
	} else {
		logger.Debug("isNftablesActive: 服务状态文件不存在: %v", err)
	}

	// 检查nftables进程
	logger.Debug("isNftablesActive: 检查 nftables 进程")
	isRunning := isProcessRunning("nftables")
	logger.Debug("isNftablesActive: nftables 进程运行状态: %t", isRunning)
	return isRunning
}

// hasIptablesRules 检查是否有iptables规则
func hasIptablesRules() bool {
	logger.Debug("hasIptablesRules: 开始检查 iptables 规则文件")

	// 检查iptables规则文件
	iptablesPaths := []string{
		"/etc/sysconfig/iptables",      // CentOS/RHEL
		"/etc/iptables/rules.v4",       // Debian/Ubuntu
		"/etc/iptables.rules",          // 其他发行版
		"/var/lib/iptables/rules-save", // 某些系统
	}

	for _, path := range iptablesPaths {
		logger.Debug("hasIptablesRules: 检查规则文件 %s", path)
		if _, err := os.Stat(path); err == nil {
			logger.Debug("hasIptablesRules: 规则文件存在: %s", path)
			// 文件存在，检查内容
			if content, err := os.ReadFile(path); err == nil {
				contentStr := string(content)
				// 检查是否有实际的规则（不只是注释和空行）
				lines := strings.Split(contentStr, "\n")
				ruleCount := 0
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "*") && !strings.HasPrefix(line, ":") && !strings.HasPrefix(line, "COMMIT") {
						ruleCount++
					}
				}
				logger.Debug("hasIptablesRules: 规则文件 %s 包含 %d 条规则", path, ruleCount)
				if ruleCount > 0 {
					logger.Debug("hasIptablesRules: 发现有效规则，iptables 已配置")
					return true
				}
			} else {
				logger.Debug("hasIptablesRules: 无法读取规则文件 %s: %v", path, err)
			}
		} else {
			logger.Debug("hasIptablesRules: 规则文件不存在: %s", path)
		}
	}

	// 检查iptables模块是否加载
	modulesPath := "/proc/modules"
	logger.Debug("hasIptablesRules: 检查 iptables 模块是否加载 %s", modulesPath)
	if content, err := os.ReadFile(modulesPath); err == nil {
		contentStr := string(content)
		hasFilter := strings.Contains(contentStr, "iptable_filter")
		hasNat := strings.Contains(contentStr, "iptable_nat")
		logger.Debug("hasIptablesRules: iptable_filter 模块加载: %t, iptable_nat 模块加载: %t", hasFilter, hasNat)
		if hasFilter || hasNat {
			logger.Debug("hasIptablesRules: iptables 模块已加载")
			return true
		}
	} else {
		logger.Debug("hasIptablesRules: 无法读取 /proc/modules: %v", err)
	}

	logger.Debug("hasIptablesRules: 未发现 iptables 规则或模块")
	return false
}

// PortUseInfo 端口使用信息结构
type PortUseInfo struct {
	Protocol string
	IP       string
	Port     string
	State    string
	Process  string // 进程名
	ExePath  string // 可执行文件路径
	Version  string // 版本号
}

// GetPortsUseInfo 获取端口使用信息
func GetPortsUseInfo() ([]PortUseInfo, error) {
	return GetPortsUseInfoWithStates([]string{"LISTEN"})
}

// GetPortsUseInfoWithStates 获取指定状态的端口使用信息
func GetPortsUseInfoWithStates(states []string) ([]PortUseInfo, error) {
	logger.Debug("GetPortsUseInfoWithStates: 开始获取端口信息，状态: %v", states)
	var ports []PortUseInfo

	// 读取 /proc/net/tcp 文件获取TCP端口
	logger.Debug("GetPortsUseInfoWithStates: 开始读取TCP端口")
	tcpPorts, err := getPortsFromProcNet("/proc/net/tcp", "tcp", states)
	if err == nil {
		ports = append(ports, tcpPorts...)
		logger.Debug("GetPortsUseInfoWithStates: TCP端口读取完成，找到 %d 个端口", len(tcpPorts))
	} else {
		logger.Debug("GetPortsUseInfoWithStates: TCP端口读取失败: %v", err)
	}

	// 读取 /proc/net/tcp6 文件获取TCP6端口
	logger.Debug("GetPortsUseInfoWithStates: 开始读取TCP6端口")
	tcp6Ports, err := getPortsFromProcNet("/proc/net/tcp6", "tcp6", states)
	if err == nil {
		ports = append(ports, tcp6Ports...)
		logger.Debug("GetPortsUseInfoWithStates: TCP6端口读取完成，找到 %d 个端口", len(tcp6Ports))
	} else {
		logger.Debug("GetPortsUseInfoWithStates: TCP6端口读取失败: %v", err)
	}

	// 读取 /proc/net/udp 文件获取UDP端口
	logger.Debug("GetPortsUseInfoWithStates: 开始读取UDP端口")
	udpPorts, err := getPortsFromProcNet("/proc/net/udp", "udp", states)
	if err == nil {
		ports = append(ports, udpPorts...)
		logger.Debug("GetPortsUseInfoWithStates: UDP端口读取完成，找到 %d 个端口", len(udpPorts))
	} else {
		logger.Debug("GetPortsUseInfoWithStates: UDP端口读取失败: %v", err)
	}

	// 读取 /proc/net/udp6 文件获取UDP6端口
	logger.Debug("GetPortsUseInfoWithStates: 开始读取UDP6端口")
	udp6Ports, err := getPortsFromProcNet("/proc/net/udp6", "udp6", states)
	if err == nil {
		ports = append(ports, udp6Ports...)
		logger.Debug("GetPortsUseInfoWithStates: UDP6端口读取完成，找到 %d 个端口", len(udp6Ports))
	} else {
		logger.Debug("GetPortsUseInfoWithStates: UDP6端口读取失败: %v", err)
	}

	logger.Debug("GetPortsUseInfoWithStates: 端口信息获取完成，总共找到 %d 个端口", len(ports))
	return ports, nil
}

// getPortsFromProcNet 从 /proc/net/* 文件读取端口信息
func getPortsFromProcNet(filePath, protocol string, allowedStates []string) ([]PortUseInfo, error) {
	logger.Debug("getPortsFromProcNet: 开始读取文件 %s, 协议 %s, 允许状态 %v", filePath, protocol, allowedStates)

	content, err := os.ReadFile(filePath)
	if err != nil {
		logger.Debug("getPortsFromProcNet: 无法读取文件 %s: %v", filePath, err)
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	var ports []PortUseInfo
	logger.Debug("getPortsFromProcNet: 文件 %s 包含 %d 行", filePath, len(lines))

	// 跳过表头行
	for i, line := range lines {
		if i == 0 {
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 解析行格式: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}

		// 解析本地地址和端口
		localAddr := parts[1] // 格式: IP:PORT (十六进制)
		addrParts := strings.Split(localAddr, ":")
		if len(addrParts) != 2 {
			continue
		}

		// 转换IP地址
		ip := parseHexIP(addrParts[0])
		if ip == "" {
			continue
		}

		// 转换端口号
		port := parseHexPort(addrParts[1])
		if port == "" {
			continue
		}

		// 检查状态字段
		state := "unknown"
		if strings.Contains(filePath, "tcp") {
			// TCP状态检查
			if len(parts) >= 4 {
				state = parseTCPState(parts[3])
			}
		} else {
			// UDP没有状态概念，默认为LISTEN
			state = "LISTEN"
		}

		// 检查状态是否在允许的列表中
		if !containsState(allowedStates, state) {
			continue
		}

		// 获取进程详细信息
		logger.Debug("getPortsFromProcNet: 开始获取端口 %s:%s 的进程信息", ip, port)
		processDetail := getProcessDetailByInode(line)

		// 创建端口信息结构
		portInfo := PortUseInfo{
			Protocol: protocol,
			IP:       ip,
			Port:     port,
			State:    state,
		}

		// 如果找到了进程，填充详细信息
		if processDetail != nil {
			portInfo.Process = processDetail.Name
			portInfo.ExePath = processDetail.ExePath

			// 尝试获取版本号（传递命令行参数）
			if version := getProcessVersion(processDetail.Name, processDetail.ExePath, processDetail.CmdLine); version != "" {
				portInfo.Version = version
			}
			logger.Debug("getPortsFromProcNet: 端口 %s:%s 匹配到进程: %s (路径: %s, 版本: %s)", ip, port, portInfo.Process, portInfo.ExePath, portInfo.Version)
		} else {
			portInfo.Process = "unknown"
		}

		ports = append(ports, portInfo)
	}

	logger.Debug("getPortsFromProcNet: 文件 %s 处理完成，找到 %d 个有效端口", filePath, len(ports))
	return ports, nil
}

// containsState 检查状态是否在允许的列表中
func containsState(allowedStates []string, state string) bool {
	for _, allowedState := range allowedStates {
		if allowedState == state {
			return true
		}
	}
	return false
}

// parseHexIP 解析十六进制IP地址
func parseHexIP(hexIP string) string {
	// /proc/net/tcp 中的IP地址是小端序（little-endian）格式
	// 例如：0100007F 表示 127.0.0.1

	// 检查是否为IPv6（长度超过8个字符）
	if len(hexIP) > 8 {
		// IPv6地址的处理
		// IPv6在/proc/net/tcp6中也是小端序，但处理较复杂
		// 这里提供基本的IPv6支持
		if hexIP == "00000000000000000000000000000000" {
			return "::"
		}
		// 简化的IPv6显示
		return fmt.Sprintf("IPv6:%s", hexIP[:8])
	}

	// 补齐到8位
	for len(hexIP) < 8 {
		hexIP = "0" + hexIP
	}

	// IPv4地址 - 小端序解析
	// 将十六进制字符串按字节分组：0100007F -> 01 00 00 7F
	// 但要按小端序读取：7F 00 00 01 -> 127.0.0.1
	ip := fmt.Sprintf("%d.%d.%d.%d",
		parseHexByte(hexIP[6:8]), // 最后一个字节是第一个IP段
		parseHexByte(hexIP[4:6]),
		parseHexByte(hexIP[2:4]),
		parseHexByte(hexIP[0:2]), // 第一个字节是最后一个IP段
	)

	// 特殊处理0.0.0.0
	if ip == "0.0.0.0" {
		return "*"
	}

	return ip
}

// parseHexByte 将两位十六进制字符串转换为整数
func parseHexByte(hexByte string) int {
	val, err := strconv.ParseInt(hexByte, 16, 64)
	if err != nil {
		return 0
	}
	return int(val)
}

// parseHexPort 解析十六进制端口号
func parseHexPort(hexPort string) string {
	port, err := strconv.ParseInt(hexPort, 16, 64)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d", port)
}

// parseTCPState 解析TCP状态
func parseTCPState(hexState string) string {
	state, err := strconv.ParseInt(hexState, 16, 64)
	if err != nil {
		return "unknown"
	}

	switch state {
	case 0x01:
		return "ESTABLISHED"
	case 0x02:
		return "SYN_SENT"
	case 0x03:
		return "SYN_RECV"
	case 0x04:
		return "FIN_WAIT1"
	case 0x05:
		return "FIN_WAIT2"
	case 0x06:
		return "TIME_WAIT"
	case 0x07:
		return "CLOSE"
	case 0x08:
		return "CLOSE_WAIT"
	case 0x09:
		return "LAST_ACK"
	case 0x0A:
		return "LISTEN"
	case 0x0B:
		return "CLOSING"
	default:
		return fmt.Sprintf("UNKNOWN_%d", state)
	}
}
