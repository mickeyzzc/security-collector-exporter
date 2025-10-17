package system

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// CheckFirewallStatus 检查防火墙状态
func CheckFirewallStatus() (bool, error) {
	// 检查firewalld
	output, err := exec.Command("systemctl", "is-active", "firewalld").Output()
	if err == nil && strings.TrimSpace(string(output)) == "active" {
		return true, nil
	}

	// 检查ufw (Ubuntu)
	output, err = exec.Command("systemctl", "is-active", "ufw").Output()
	if err == nil && strings.TrimSpace(string(output)) == "active" {
		return true, nil
	}

	// 检查iptables服务
	output, err = exec.Command("systemctl", "is-active", "iptables").Output()
	if err == nil && strings.TrimSpace(string(output)) == "active" {
		return true, nil
	}

	// 直接检查iptables规则
	output, err = exec.Command("iptables", "-L").Output()
	if err == nil && strings.Contains(string(output), "Chain INPUT") {
		// 简单判断是否有非默认规则
		if strings.Count(string(output), "ACCEPT") > 3 {
			return true, nil
		}
	}

	return false, nil
}

// PortUseInfo 端口使用信息结构
type PortUseInfo struct {
	Protocol string
	IP       string
	Port     string
	State    string
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

		ports = append(ports, PortUseInfo{
			Protocol: protocol,
			IP:       ip,
			Port:     port,
			State:    state,
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
