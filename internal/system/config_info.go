package system

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// SSHConfigInfo SSH配置信息结构
type SSHConfigInfo struct {
	Key   string
	Value string
}

// GetSSHConfigInfo 获取SSH配置信息
func GetSSHConfigInfo() ([]SSHConfigInfo, error) {
	var configs []SSHConfigInfo

	sshConfigPath := "/etc/ssh/sshd_config"
	if _, err := os.Stat(sshConfigPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("sshd_config not found")
	}

	content, err := os.ReadFile(sshConfigPath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// 跳过空行和注释行
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析key=value格式
		parts := strings.SplitN(line, " ", 2)
		if len(parts) >= 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			// 只收集有值的配置项
			if key != "" && value != "" {
				configs = append(configs, SSHConfigInfo{
					Key:   key,
					Value: value,
				})
			}
		}
	}

	return configs, nil
}

// LoginDefsInfo login.defs配置信息结构
type LoginDefsInfo struct {
	Key       string
	Value     string
	NumValue  float64
	IsNumeric bool
}

// GetLoginDefsInfo 获取login.defs配置信息
func GetLoginDefsInfo() ([]LoginDefsInfo, error) {
	var configs []LoginDefsInfo

	content, err := os.ReadFile("/etc/login.defs")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// 跳过空行和注释行
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析key value格式（用空格或制表符分隔）
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			// 只收集有值的配置项
			if key != "" && value != "" {
				// 检查value是否为数字
				if numValue, err := strconv.ParseFloat(value, 64); err == nil {
					// 是数字，设置value为"num"，并保存数值
					configs = append(configs, LoginDefsInfo{
						Key:       key,
						Value:     "num",
						NumValue:  numValue,
						IsNumeric: true,
					})
				} else {
					// 不是数字，保持原值
					configs = append(configs, LoginDefsInfo{
						Key:       key,
						Value:     value,
						NumValue:  0,
						IsNumeric: false,
					})
				}
			}
		}
	}

	return configs, nil
}

// SELinuxConfigInfo SELinux配置信息结构
type SELinuxConfigInfo struct {
	Key   string
	Value string
}

// GetSELinuxConfigInfo 获取SELinux配置信息
func GetSELinuxConfigInfo() ([]SELinuxConfigInfo, error) {
	var configs []SELinuxConfigInfo

	content, err := os.ReadFile("/etc/selinux/config")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// 跳过空行和注释行
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析key=value格式
		parts := strings.SplitN(line, "=", 2)
		if len(parts) >= 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			// 只收集有值的配置项
			if key != "" && value != "" {
				configs = append(configs, SELinuxConfigInfo{
					Key:   key,
					Value: value,
				})
			}
		}
	}

	return configs, nil
}

// HostsOptionInfo hosts配置信息结构
type HostsOptionInfo struct {
	File    string // 文件名: hosts.deny 或 hosts.allow
	Service string // 服务名
	Host    string // 主机/网络
	Action  string // 动作: deny 或 allow
}

// GetHostsOptionsInfo 获取hosts.deny和hosts.allow配置信息
func GetHostsOptionsInfo() ([]HostsOptionInfo, error) {
	var options []HostsOptionInfo

	// 读取hosts.deny文件
	hostsDenyPath := "/etc/hosts.deny"
	if content, err := os.ReadFile(hostsDenyPath); err == nil {
		denyOptions := parseHostsFile(content, "hosts.deny", "deny")
		options = append(options, denyOptions...)
	}

	// 读取hosts.allow文件
	hostsAllowPath := "/etc/hosts.allow"
	if content, err := os.ReadFile(hostsAllowPath); err == nil {
		allowOptions := parseHostsFile(content, "hosts.allow", "allow")
		options = append(options, allowOptions...)
	}

	return options, nil
}

// parseHostsFile 解析hosts文件内容
func parseHostsFile(content []byte, fileName, action string) []HostsOptionInfo {
	var options []HostsOptionInfo

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// 跳过空行和注释行
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析格式: service: host[,host...]
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		service := strings.TrimSpace(parts[0])
		hostsPart := strings.TrimSpace(parts[1])

		// 处理多个主机（逗号分隔）
		hosts := strings.Split(hostsPart, ",")
		for _, host := range hosts {
			host = strings.TrimSpace(host)
			if host != "" {
				options = append(options, HostsOptionInfo{
					File:    fileName,
					Service: service,
					Host:    host,
					Action:  action,
				})
			}
		}
	}

	return options
}
