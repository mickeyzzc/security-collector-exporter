package system

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// FirewallInfo 防火墙信息结构
type FirewallInfo struct {
	Enabled bool   // 是否启用
	Type    string // 防火墙类型
}

// CheckFirewallStatus 检查防火墙状态
func CheckFirewallStatus() (FirewallInfo, error) {
	// 1. 检查firewalld服务状态
	if isFirewalldActive() {
		return FirewallInfo{Enabled: true, Type: "firewalld"}, nil
	}

	// 2. 检查ufw服务状态 (Ubuntu)
	if isUfwActive() {
		return FirewallInfo{Enabled: true, Type: "ufw"}, nil
	}

	// 3. 检查iptables服务状态
	if isIptablesActive() {
		return FirewallInfo{Enabled: true, Type: "iptables"}, nil
	}

	// 4. 检查iptables规则文件
	if hasIptablesRules() {
		return FirewallInfo{Enabled: true, Type: "iptables"}, nil
	}

	// 5. 检查nftables
	if isNftablesActive() {
		return FirewallInfo{Enabled: true, Type: "nftables"}, nil
	}

	return FirewallInfo{Enabled: false, Type: "none"}, nil
}

// isFirewalldActive 检查firewalld是否激活
func isFirewalldActive() bool {
	// 检查systemd服务状态文件
	serviceStatePath := "/run/systemd/system/firewalld.service"
	if _, err := os.Stat(serviceStatePath); err == nil {
		if content, err := os.ReadFile(serviceStatePath); err == nil {
			return strings.Contains(string(content), "ActiveState=active")
		}
	}

	// 检查firewalld进程
	return isProcessRunning("firewalld")
}

// isUfwActive 检查ufw是否激活
func isUfwActive() bool {
	// 检查systemd服务状态文件
	serviceStatePath := "/run/systemd/system/ufw.service"
	if _, err := os.Stat(serviceStatePath); err == nil {
		if content, err := os.ReadFile(serviceStatePath); err == nil {
			return strings.Contains(string(content), "ActiveState=active")
		}
	}

	// 检查ufw状态文件
	ufwStatusPath := "/var/lib/ufw/ufw-not-booted"
	if _, err := os.Stat(ufwStatusPath); os.IsNotExist(err) {
		// 如果状态文件不存在，说明ufw可能已启动
		return true
	}

	// 检查ufw进程
	return isProcessRunning("ufw")
}

// isIptablesActive 检查iptables服务是否激活
func isIptablesActive() bool {
	// 检查systemd服务状态文件
	serviceStatePath := "/run/systemd/system/iptables.service"
	if _, err := os.Stat(serviceStatePath); err == nil {
		if content, err := os.ReadFile(serviceStatePath); err == nil {
			return strings.Contains(string(content), "ActiveState=active")
		}
	}

	// 检查iptables进程
	return isProcessRunning("iptables")
}

// isNftablesActive 检查nftables是否激活
func isNftablesActive() bool {
	// 检查systemd服务状态文件
	serviceStatePath := "/run/systemd/system/nftables.service"
	if _, err := os.Stat(serviceStatePath); err == nil {
		if content, err := os.ReadFile(serviceStatePath); err == nil {
			return strings.Contains(string(content), "ActiveState=active")
		}
	}

	// 检查nftables进程
	return isProcessRunning("nftables")
}

// hasIptablesRules 检查是否有iptables规则
func hasIptablesRules() bool {
	// 检查iptables规则文件
	iptablesPaths := []string{
		"/etc/sysconfig/iptables",      // CentOS/RHEL
		"/etc/iptables/rules.v4",       // Debian/Ubuntu
		"/etc/iptables.rules",          // 其他发行版
		"/var/lib/iptables/rules-save", // 某些系统
	}

	for _, path := range iptablesPaths {
		if _, err := os.Stat(path); err == nil {
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
				if ruleCount > 0 {
					return true
				}
			}
		}
	}

	// 检查iptables模块是否加载
	modulesPath := "/proc/modules"
	if content, err := os.ReadFile(modulesPath); err == nil {
		contentStr := string(content)
		if strings.Contains(contentStr, "iptable_filter") || strings.Contains(contentStr, "iptable_nat") {
			return true
		}
	}

	return false
}

// PortUseInfo 端口使用信息结构
type PortUseInfo struct {
	Protocol string
	IP       string
	Port     string
	State    string
	Process  string // 进程名
}

// GetPortsUseInfo 获取端口使用信息
func GetPortsUseInfo() ([]PortUseInfo, error) {
	return GetPortsUseInfoWithStates([]string{"LISTEN"})
}

// GetPortsUseInfoWithStates 获取指定状态的端口使用信息
func GetPortsUseInfoWithStates(states []string) ([]PortUseInfo, error) {
	var ports []PortUseInfo

	// 读取 /proc/net/tcp 文件获取TCP端口
	tcpPorts, err := getPortsFromProcNet("/proc/net/tcp", "tcp", states)
	if err == nil {
		ports = append(ports, tcpPorts...)
	}

	// 读取 /proc/net/tcp6 文件获取TCP6端口
	tcp6Ports, err := getPortsFromProcNet("/proc/net/tcp6", "tcp6", states)
	if err == nil {
		ports = append(ports, tcp6Ports...)
	}

	// 读取 /proc/net/udp 文件获取UDP端口
	udpPorts, err := getPortsFromProcNet("/proc/net/udp", "udp", states)
	if err == nil {
		ports = append(ports, udpPorts...)
	}

	// 读取 /proc/net/udp6 文件获取UDP6端口
	udp6Ports, err := getPortsFromProcNet("/proc/net/udp6", "udp6", states)
	if err == nil {
		ports = append(ports, udp6Ports...)
	}

	return ports, nil
}

// getPortsFromProcNet 从 /proc/net/* 文件读取端口信息
func getPortsFromProcNet(filePath, protocol string, allowedStates []string) ([]PortUseInfo, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	var ports []PortUseInfo

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

		// 获取进程信息
		processName := getProcessByInode(line)

		ports = append(ports, PortUseInfo{
			Protocol: protocol,
			IP:       ip,
			Port:     port,
			State:    state,
			Process:  processName,
		})
	}

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
	// 移除前导零
	hexIP = strings.TrimLeft(hexIP, "0")
	if hexIP == "" {
		hexIP = "0"
	}

	// 转换十六进制到整数
	ipInt, err := strconv.ParseInt(hexIP, 16, 64)
	if err != nil {
		return ""
	}

	// 检查是否为IPv6
	if len(hexIP) > 8 {
		// IPv6地址，简化处理
		return fmt.Sprintf("::%d", ipInt)
	}

	// IPv4地址
	ip := fmt.Sprintf("%d.%d.%d.%d",
		(ipInt>>24)&0xFF,
		(ipInt>>16)&0xFF,
		(ipInt>>8)&0xFF,
		ipInt&0xFF,
	)

	// 特殊处理0.0.0.0
	if ip == "0.0.0.0" {
		return "*"
	}

	return ip
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
