# Linux安全配置检查清单

基于Linux安全配置标准文档的合规性检查清单。

## 检查项目

### 1. 账户管理
- [ ] **创建cnet账户** - `linux_security_account_info{username="cnet"}`
- [ ] **禁用root直接SSH登录** - `linux_security_sshd_config_info{key="PermitRootLogin", value="no"}`
- [ ] **移除不必要账户** - 通过 `linux_security_account_info` 检查账户信息

### 2. 密码策略
- [ ] **密码最大有效期90天** - `linux_security_login_defs_info{key="PASS_MAX_DAYS", value="num"} <= 90`
- [ ] **密码最小长度10位** - `linux_security_login_defs_info{key="PASS_MIN_LEN", value="num"} >= 10`
- [ ] **密码警告天数7天** - `linux_security_login_defs_info{key="PASS_WARN_AGE", value="num"} == 7`

### 3. 系统安全配置
- [ ] **SELinux强制模式** - `linux_security_selinux_config{key="SELINUX", value="enforcing"}`
- [ ] **防火墙启用** - `linux_security_firewall_enabled{firewall_type!="none"} == 1`
- [ ] **TCP Wrappers配置** - `linux_security_hosts_options_info{file="hosts.deny", service="ALL", host="ALL", action="deny"}`
- [ ] **端口使用监控** - `linux_security_ports_use_info{process!="unknown"}`

### 4. 系统服务
- [ ] **禁用X Window** - `linux_security_services_info{service_name="xwindow", is_running="false"}`
- [ ] **系统运行级别正确** - `linux_security_system_target_info{current_target="multi-user.target"}`
- [ ] **无运行中的不必要服务** - `count(linux_security_services_info{service_name=~"nfs|cups|bluetooth|avahi-daemon|rpcbind|postfix", is_running="true"}) == 0`

### 5. 系统维护
- [ ] **系统补丁信息** - `linux_security_patch_info{last_patch_time!="unknown"}`

## Prometheus告警规则

```yaml
groups:
- name: linux_security_compliance
  rules:
  # 关键安全告警
  - alert: RootSSHLoginEnabled
    expr: linux_security_sshd_config_info{key="PermitRootLogin", value="yes"}
    for: 0m
    labels:
      severity: critical
      category: security
    annotations:
      summary: "Root SSH direct login is enabled"
      description: "Root account can login directly via SSH, which violates security policy"

  - alert: SELinuxNotEnforcing
    expr: linux_security_selinux_config{key="SELINUX", value=~"permissive|disabled"}
    for: 0m
    labels:
      severity: warning
      category: security
    annotations:
      summary: "SELinux is not in enforcing mode"
      description: "SELinux should be in enforcing mode for better security"

  - alert: SELinuxDisabled
    expr: linux_security_selinux_config{key="SELINUX", value="disabled"}
    for: 0m
    labels:
      severity: critical
      category: security
    annotations:
      summary: "SELinux is disabled"
      description: "SELinux should be enabled for better security"

  - alert: FirewallDisabled
    expr: linux_security_firewall_enabled{firewall_type="none"} == 1
    for: 0m
    labels:
      severity: warning
      category: security
    annotations:
      summary: "Firewall is disabled"
      description: "System firewall should be enabled to protect against network attacks"

  - alert: UnknownProcessUsingPort
    expr: linux_security_ports_use_info{process="unknown"} == 1
    for: 0m
    labels:
      severity: warning
      category: security
    annotations:
      summary: "Unknown process using port"
      description: "Port {{ $labels.port }} is being used by an unknown process"

  # 密码策略告警
  - alert: PasswordMaxDaysTooLong
    expr: linux_security_login_defs_info{key="PASS_MAX_DAYS", value="num"} > 90
    for: 0m
    labels:
      severity: warning
      category: password_policy
    annotations:
      summary: "Password max days is too long"
      description: "Password max days should be 90 or fewer days"

  - alert: PasswordMinLengthTooShort
    expr: linux_security_login_defs_info{key="PASS_MIN_LEN", value="num"} < 10
    for: 0m
    labels:
      severity: warning
      category: password_policy
    annotations:
      summary: "Password min length is too short"
      description: "Password min length should be 10 or more characters"

  # 系统配置告警
  - alert: XWindowEnabled
    expr: linux_security_services_info{service_name="xwindow", is_running="true"}
    for: 0m
    labels:
      severity: info
      category: system_config
    annotations:
      summary: "X Window System is enabled"
      description: "X Window System should be disabled on servers"

  - alert: UnnecessaryServicesRunning
    expr: count(linux_security_services_info{service_name=~"nfs|cups|bluetooth|avahi-daemon|rpcbind|postfix", is_running="true"}) > 0
    for: 0m
    labels:
      severity: warning
      category: system_config
    annotations:
      summary: "Unnecessary services are running"
      description: "{{ $value }} unnecessary services are currently running"

  - alert: UnnecessaryAccountsPresent
    expr: count(linux_security_account_info{username=~"games|news|uucp|proxy|www-data|backup|list|irc|gnats|nobody|libuuid|syslog|messagebus|landscape|sshd|ubuntu|debian|systemd-timesync|systemd-network|systemd-resolve|systemd-bus-proxy|_apt|lxd|dnsmasq|libvirt-qemu|libvirt-dnsmasq|Debian-exim|statd|tcpdump|tss|geoclue|pulse|rtkit|saned|usbmux|colord|avahi|cups-pk-helper|speech-dispatcher|whoopsie|kernoops|hplip|saned|pulse|rtkit|usbmux|colord|avahi|speech-dispatcher|whoopsie|kernoops|hplip"}) > 0
    for: 0m
    labels:
      severity: info
      category: system_config
    annotations:
      summary: "Unnecessary accounts present"
      description: "{{ $value }} unnecessary accounts found in the system"

  # 系统维护告警
  - alert: SystemPatchInfoUnknown
    expr: linux_security_patch_info{last_patch_time="unknown"}
    for: 0m
    labels:
      severity: warning
      category: maintenance
    annotations:
      summary: "System patch information is unknown"
      description: "Cannot determine last patch time for {{ $labels.package_type }} system"
```

## 合规性评分

可以使用以下PromQL查询计算系统安全合规性评分：

```promql
# 计算安全合规性评分 (0-100分)
(
  (linux_security_sshd_config_info{key="PermitRootLogin", value="no"} or vector(0)) * 20 +
  (linux_security_selinux_config{key="SELINUX", value="enforcing"} or vector(0)) * 15 +
  (linux_security_firewall_enabled == 1) * 15 +
  ((linux_security_login_defs_info{key="PASS_MIN_LEN", value="num"} >= 10) or vector(0)) * 10 +
  ((linux_security_login_defs_info{key="PASS_MAX_DAYS", value="num"} <= 90) or vector(0)) * 10 +
  (linux_security_services_info{service_name="xwindow", is_running="false"} or vector(0)) * 5 +
  (count(linux_security_services_info{service_name=~"nfs|cups|bluetooth|avahi-daemon|rpcbind|postfix", is_running="true"}) == 0) * 10 +
  (linux_security_hosts_options_info{file="hosts.deny", service="ALL", host="ALL", action="deny"} or vector(0)) * 5
)
```

## 检查频率建议

- **实时监控**: 关键安全配置（SELinux、防火墙、SSH配置）
- **每小时检查**: 服务状态、账户状态
- **每日检查**: 密码策略、系统补丁状态
- **每周检查**: 完整合规性评估

## 新增查询示例

### 防火墙类型检查

```promql
# 检查特定防火墙类型
linux_security_firewall_enabled{firewall_type="firewalld"}
linux_security_firewall_enabled{firewall_type="ufw"}
linux_security_firewall_enabled{firewall_type="iptables"}

# 统计启用的防火墙数量
sum(linux_security_firewall_enabled)
```

### 端口进程监控

```promql
# 查询特定进程的端口使用
linux_security_ports_use_info{process="sshd"}
linux_security_ports_use_info{process="nginx"}
linux_security_ports_use_info{process="mysql"}

# 查询特定端口的进程
linux_security_ports_use_info{port="22"}
linux_security_ports_use_info{port="80"}
linux_security_ports_use_info{port="443"}

# 统计各进程的端口数量
count by (process) (linux_security_ports_use_info)

# 查询未知进程占用的端口
linux_security_ports_use_info{process="unknown"}
```

### 服务状态监控

```promql
# 查询特定服务的状态
linux_security_services_info{service_name="sshd"}
linux_security_services_info{service_name="nginx"}

# 查询运行中的服务
linux_security_services_info{is_running="true"}

# 查询启用的服务
linux_security_services_info{is_enabled="true"}

# 统计各类型服务的数量
count by (service_type) (linux_security_services_info)
```

## 修复建议

当发现安全配置问题时，请参考原始安全标准文档进行修复：

1. **账户管理问题**: 创建cnet账户，禁用root SSH登录
2. **密码策略问题**: 修改`/etc/login.defs`和`/etc/security/pwquality.conf`
3. **SELinux问题**: 修改`/etc/selinux/config`并重启系统
4. **防火墙问题**: 配置iptables或nftables规则
5. **服务问题**: 禁用不必要的服务和X Window
6. **补丁问题**: 运行系统更新命令
7. **端口监控**: 识别并管理未知进程占用的端口
