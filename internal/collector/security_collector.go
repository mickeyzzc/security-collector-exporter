package collector

import (
	"fmt"
	"security-exporter/internal/system"
	"security-exporter/pkg/config"
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

	// Shadow 指标
	lastPasswordChange *prometheus.Desc
	passwordMaxDays    *prometheus.Desc
	passwordMinDays    *prometheus.Desc
	passwordWarnDays   *prometheus.Desc
	passwordInactive   *prometheus.Desc
	accountExpire      *prometheus.Desc

	// 密码策略指标
	loginDefsInfo *prometheus.Desc

	// SELinux指标
	selinuxConfig *prometheus.Desc

	// 防火墙指标
	firewallEnabled *prometheus.Desc
	portsUseInfo    *prometheus.Desc

	// 组件状态指标
	servicesInfo  *prometheus.Desc
	lastPatchTime *prometheus.Desc
	packageCount  *prometheus.Desc

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
				"pretty_name", "os_name", "version", "version_id", "id", "id_like",
				"home_url", "bug_report_url", "support_url", "variant", "variant_id",
				"cpe_name", "build_id", "image_id", "image_version", "redhat_release",
			}, nil,
		),
		accountInfo: prometheus.NewDesc(
			"linux_security_account_info",
			"系统账户信息",
			[]string{"username", "home_dir", "shell", "primary_group", "other_groups", "has_sudo"}, nil,
		),
		lastPasswordChange: prometheus.NewDesc(
			"linux_security_last_password_change",
			"最后密码修改时间（天数）",
			[]string{"username"}, nil,
		),
		passwordMaxDays: prometheus.NewDesc(
			"linux_security_password_max_days",
			"密码最大有效期（天数）",
			[]string{"username"}, nil,
		),
		passwordMinDays: prometheus.NewDesc(
			"linux_security_password_min_days",
			"密码最小有效期（天数）",
			[]string{"username"}, nil,
		),
		passwordWarnDays: prometheus.NewDesc(
			"linux_security_password_warn_days",
			"密码警告天数",
			[]string{"username"}, nil,
		),
		passwordInactive: prometheus.NewDesc(
			"linux_security_password_inactive",
			"密码不活跃天数",
			[]string{"username"}, nil,
		),
		accountExpire: prometheus.NewDesc(
			"linux_security_account_expire",
			"账户过期时间（天数）",
			[]string{"username"}, nil,
		),
		sshdConfigInfo: prometheus.NewDesc(
			"linux_security_sshd_config_info",
			"SSH服务配置信息",
			[]string{"info_key", "info_value"}, nil,
		),
		loginDefsInfo: prometheus.NewDesc(
			"linux_security_login_defs_info",
			"login.defs配置信息",
			[]string{"info_key", "info_value"}, nil,
		),
		selinuxConfig: prometheus.NewDesc(
			"linux_security_selinux_config",
			"SELinux配置信息",
			[]string{"info_key", "info_value"}, nil,
		),
		firewallEnabled: prometheus.NewDesc(
			"linux_security_firewall_enabled",
			"防火墙是否启用 (1=启用, 0=禁用)",
			[]string{"firewall_type", "is_running"}, nil,
		),
		portsUseInfo: prometheus.NewDesc(
			"linux_security_ports_use_info",
			"系统端口使用信息",
			[]string{"protocol", "local_ip", "local_port", "state", "process", "exe_path", "version", "app_name"}, nil,
		),
		servicesInfo: prometheus.NewDesc(
			"linux_security_services_info",
			"系统服务信息",
			[]string{"service_name", "is_running", "service_type", "is_enabled"}, nil,
		),
		lastPatchTime: prometheus.NewDesc(
			"linux_security_last_patch_time",
			"最后一次补丁时间",
			[]string{"package_type"},
			nil,
		),
		packageCount: prometheus.NewDesc(
			"linux_security_package_count",
			"已安装包数量",
			[]string{"package_type"},
			nil,
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
	ch <- c.lastPasswordChange
	ch <- c.passwordMaxDays
	ch <- c.passwordMinDays
	ch <- c.passwordWarnDays
	ch <- c.passwordInactive
	ch <- c.accountExpire
	ch <- c.sshdConfigInfo
	ch <- c.loginDefsInfo
	ch <- c.selinuxConfig
	ch <- c.firewallEnabled
	ch <- c.portsUseInfo
	ch <- c.servicesInfo
	ch <- c.lastPatchTime
	ch <- c.packageCount
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

	// 收集拆分的shadow指标
	shadowMetrics, err := system.GetAllShadowMetrics()
	if err == nil {
		// 最后密码修改时间
		for _, metric := range shadowMetrics.LastPasswordChange {
			ch <- prometheus.MustNewConstMetric(
				c.lastPasswordChange,
				prometheus.GaugeValue,
				metric.Value,
				metric.Username,
			)
		}

		// 密码最大有效期
		for _, metric := range shadowMetrics.PasswordMaxDays {
			ch <- prometheus.MustNewConstMetric(
				c.passwordMaxDays,
				prometheus.GaugeValue,
				metric.Value,
				metric.Username,
			)
		}

		// 密码最小有效期
		for _, metric := range shadowMetrics.PasswordMinDays {
			ch <- prometheus.MustNewConstMetric(
				c.passwordMinDays,
				prometheus.GaugeValue,
				metric.Value,
				metric.Username,
			)
		}

		// 密码警告天数
		for _, metric := range shadowMetrics.PasswordWarnDays {
			ch <- prometheus.MustNewConstMetric(
				c.passwordWarnDays,
				prometheus.GaugeValue,
				metric.Value,
				metric.Username,
			)
		}

		// 密码不活跃天数
		for _, metric := range shadowMetrics.PasswordInactive {
			ch <- prometheus.MustNewConstMetric(
				c.passwordInactive,
				prometheus.GaugeValue,
				metric.Value,
				metric.Username,
			)
		}

		// 账户过期时间
		for _, metric := range shadowMetrics.AccountExpire {
			ch <- prometheus.MustNewConstMetric(
				c.accountExpire,
				prometheus.GaugeValue,
				metric.Value,
				metric.Username,
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
			fmt.Sprintf("%t", firewallInfo.IsRunning),
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
				port.ExePath,
				port.Version,
				port.App,
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

	// 获取补丁时间信息
	patchTimeInfo, err := system.GetPatchTimeInfo()
	if err == nil {
		ch <- prometheus.MustNewConstMetric(
			c.lastPatchTime,
			prometheus.GaugeValue,
			1, // 每个补丁时间信息条目值为1
			patchTimeInfo.PackageType,
		)
	}

	// 获取包数量信息
	packageCountInfo, err := system.GetPackageCountInfo()
	if err == nil {
		ch <- prometheus.MustNewConstMetric(
			c.packageCount,
			prometheus.GaugeValue,
			float64(packageCountInfo.PackageCount),
			packageCountInfo.PackageType,
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
