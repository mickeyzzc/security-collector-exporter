package collector

import (
	"fmt"
	"security-exporter/internal/config"
	"security-exporter/internal/system"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// SecurityCollector 实现Prometheus的Collector接口
type SecurityCollector struct {
	// 配置
	config *config.Config

	// 系统基础信息指标
	osVersionInfo  *prometheus.Desc
	accountInfo    *prometheus.Desc
	sshdConfigInfo *prometheus.Desc

	// 密码策略指标
	loginDefsInfo *prometheus.Desc

	// SELinux指标
	selinuxConfig *prometheus.Desc

	// 防火墙指标
	firewallEnabled *prometheus.Desc
	portsUseInfo    *prometheus.Desc

	// 组件状态指标
	servicesInfo *prometheus.Desc
	patchInfo    *prometheus.Desc

	// 新增安全标准检查指标
	hostsOptionsInfo *prometheus.Desc
	systemTargetInfo *prometheus.Desc
}

// NewSecurityCollector 创建一个新的安全信息收集器
func NewSecurityCollector(cfg *config.Config) *SecurityCollector {
	return &SecurityCollector{
		config: cfg,
		osVersionInfo: prometheus.NewDesc(
			"linux_security_os_version_info",
			"Linux操作系统版本信息",
			[]string{
				"pretty_name", "name", "version", "version_id", "id", "id_like",
				"home_url", "bug_report_url", "support_url", "variant", "variant_id",
				"cpe_name", "build_id", "image_id", "image_version", "redhat_release",
			}, nil,
		),
		accountInfo: prometheus.NewDesc(
			"linux_security_account_info",
			"系统账户信息",
			[]string{"username", "home_dir", "shell", "primary_group", "groups", "has_sudo"}, nil,
		),
		sshdConfigInfo: prometheus.NewDesc(
			"linux_security_sshd_config_info",
			"SSH服务配置信息",
			[]string{"key", "value"}, nil,
		),
		loginDefsInfo: prometheus.NewDesc(
			"linux_security_login_defs_info",
			"login.defs配置信息",
			[]string{"key", "value"}, nil,
		),
		selinuxConfig: prometheus.NewDesc(
			"linux_security_selinux_config",
			"SELinux配置信息",
			[]string{"key", "value"}, nil,
		),
		firewallEnabled: prometheus.NewDesc(
			"linux_security_firewall_enabled",
			"防火墙是否启用 (1=启用, 0=禁用)",
			[]string{"firewall_type"}, nil,
		),
		portsUseInfo: prometheus.NewDesc(
			"linux_security_ports_use_info",
			"系统端口使用信息",
			[]string{"protocol", "ip", "port", "state", "process"}, nil,
		),
		servicesInfo: prometheus.NewDesc(
			"linux_security_services_info",
			"系统服务信息",
			[]string{"service_name", "is_running", "service_type", "is_enabled"}, nil,
		),
		patchInfo: prometheus.NewDesc(
			"linux_security_patch_info",
			"系统补丁信息",
			[]string{"last_patch_time", "package_type", "package_count"}, nil,
		),
		hostsOptionsInfo: prometheus.NewDesc(
			"linux_security_hosts_options_info",
			"hosts.deny和hosts.allow配置信息",
			[]string{"file", "service", "host", "action"}, nil,
		),
		systemTargetInfo: prometheus.NewDesc(
			"linux_security_system_target_info",
			"系统目标信息",
			[]string{"current_target", "target_type"}, nil,
		),
	}
}

// Describe 实现Collector接口的Describe方法
func (c *SecurityCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.osVersionInfo
	ch <- c.accountInfo
	ch <- c.sshdConfigInfo
	ch <- c.loginDefsInfo
	ch <- c.selinuxConfig
	ch <- c.firewallEnabled
	ch <- c.portsUseInfo
	ch <- c.servicesInfo
	ch <- c.patchInfo
	ch <- c.hostsOptionsInfo
	ch <- c.systemTargetInfo
}

// Collect 实现Collector接口的Collect方法
func (c *SecurityCollector) Collect(ch chan<- prometheus.Metric) {
	// 收集系统版本信息
	osVersionInfo, err := system.GetOSVersionInfo()
	if err == nil {
		ch <- prometheus.MustNewConstMetric(
			c.osVersionInfo,
			prometheus.GaugeValue,
			1,
			osVersionInfo.PrettyName,
			osVersionInfo.Name,
			osVersionInfo.Version,
			osVersionInfo.VersionID,
			osVersionInfo.ID,
			osVersionInfo.IDLike,
			osVersionInfo.HomeURL,
			osVersionInfo.BugReportURL,
			osVersionInfo.SupportURL,
			osVersionInfo.Variant,
			osVersionInfo.VariantID,
			osVersionInfo.CPEName,
			osVersionInfo.BuildID,
			osVersionInfo.ImageID,
			osVersionInfo.ImageVersion,
			osVersionInfo.RedHatRelease,
		)
	}

	// 收集所有账户信息
	accounts, err := system.GetAllAccountInfo()
	if err == nil {
		for _, account := range accounts {
			// 将组列表转换为逗号分隔的字符串
			groupsStr := strings.Join(account.Groups, ",")

			ch <- prometheus.MustNewConstMetric(
				c.accountInfo,
				prometheus.GaugeValue,
				1,
				account.Username,
				account.HomeDir,
				account.Shell,
				account.PrimaryGroup,
				groupsStr,
				fmt.Sprintf("%t", account.HasSudo),
			)
		}
	}

	// 收集SSH配置信息
	sshConfigs, err := system.GetSSHConfigInfo()
	if err == nil {
		for _, config := range sshConfigs {
			ch <- prometheus.MustNewConstMetric(
				c.sshdConfigInfo,
				prometheus.GaugeValue,
				1,
				config.Key,
				config.Value,
			)
		}
	}

	// 收集login.defs配置信息
	loginDefsConfigs, err := system.GetLoginDefsInfo()
	if err == nil {
		for _, config := range loginDefsConfigs {
			// 如果是数字类型，使用数值作为指标值；否则使用1
			var metricValue float64
			if config.IsNumeric {
				metricValue = config.NumValue
			} else {
				metricValue = 1
			}

			ch <- prometheus.MustNewConstMetric(
				c.loginDefsInfo,
				prometheus.GaugeValue,
				metricValue,
				config.Key,
				config.Value,
			)
		}
	}

	// 收集SELinux配置信息
	selinuxConfigs, err := system.GetSELinuxConfigInfo()
	if err == nil {
		for _, config := range selinuxConfigs {
			ch <- prometheus.MustNewConstMetric(
				c.selinuxConfig,
				prometheus.GaugeValue,
				1,
				config.Key,
				config.Value,
			)
		}
	}

	// 检查防火墙状态
	firewallInfo, err := system.CheckFirewallStatus()
	if err == nil {
		ch <- prometheus.MustNewConstMetric(
			c.firewallEnabled,
			prometheus.GaugeValue,
			system.BoolToFloat64(firewallInfo.Enabled),
			firewallInfo.Type,
		)
	}

	// 获取端口使用信息
	portsInfo, err := system.GetPortsUseInfoWithStates(c.config.PortStates)
	if err == nil {
		for _, port := range portsInfo {
			ch <- prometheus.MustNewConstMetric(
				c.portsUseInfo,
				prometheus.GaugeValue,
				1,
				port.Protocol,
				port.IP,
				port.Port,
				port.State,
				port.Process,
			)
		}
	}

	// 获取所有服务信息
	servicesInfo, err := system.GetAllServicesInfo()
	if err == nil {
		for _, service := range servicesInfo {
			ch <- prometheus.MustNewConstMetric(
				c.servicesInfo,
				prometheus.GaugeValue,
				1, // 每个服务条目值为1
				service.Name,
				fmt.Sprintf("%t", service.IsRunning),
				service.ServiceType,
				fmt.Sprintf("%t", service.IsEnabled),
			)
		}
	}

	// 获取补丁信息
	patchInfo, err := system.GetPatchInfo()
	if err == nil {
		ch <- prometheus.MustNewConstMetric(
			c.patchInfo,
			prometheus.GaugeValue,
			1, // 每个补丁信息条目值为1
			patchInfo.LastPatchTime,
			patchInfo.PackageType,
			fmt.Sprintf("%d", patchInfo.PackageCount),
		)
	}

	// 获取hosts配置信息
	hostsOptions, err := system.GetHostsOptionsInfo()
	if err == nil {
		for _, option := range hostsOptions {
			ch <- prometheus.MustNewConstMetric(
				c.hostsOptionsInfo,
				prometheus.GaugeValue,
				1, // 每个配置条目值为1
				option.File,
				option.Service,
				option.Host,
				option.Action,
			)
		}
	}

	// 获取系统目标信息
	systemTargetInfo, err := system.GetSystemTargetInfo()
	if err == nil {
		ch <- prometheus.MustNewConstMetric(
			c.systemTargetInfo,
			prometheus.GaugeValue,
			1, // 每个系统目标信息条目值为1
			systemTargetInfo.CurrentTarget,
			systemTargetInfo.TargetType,
		)
	}
}
