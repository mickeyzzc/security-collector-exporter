# Linux安全配置检查清单

基于Linux安全配置标准文档的合规性检查清单。

## 检查项目

### 1. 账户管理
- [ ] **创建cnet账户** - `linux_security_account_info{username="cnet"}`
- [ ] **禁用root直接SSH登录** - `linux_security_sshd_config_info{info_key="PermitRootLogin", info_value="no"}`
- [ ] **移除不必要账户** - 通过 `linux_security_account_info` 检查账户信息
- [ ] **检查账户密码策略** - 通过 `linux_security_password_max_days` 检查密码有效期

### 2. 密码策略
- [ ] **密码最大有效期90天** - `linux_security_login_defs_info{info_key="PASS_MAX_DAYS", info_value="num"} <= 90`
- [ ] **密码最小长度10位** - `linux_security_login_defs_info{info_key="PASS_MIN_LEN", info_value="num"} >= 10`
- [ ] **密码警告天数7天** - `linux_security_login_defs_info{info_key="PASS_WARN_AGE", info_value="num"} == 7`

### 3. 系统安全配置
- [ ] **SELinux强制模式** - `linux_security_selinux_config{info_key="SELINUX", info_value="enforcing"}`
- [ ] **防火墙启用** - `linux_security_firewall_enabled{firewall_type!="none"} == 1`
- [ ] **防火墙正在运行** - `linux_security_firewall_enabled{firewall_type!="none", is_running="true"} == 1`
- [ ] **TCP Wrappers配置** - `linux_security_hosts_options_info{file="hosts.deny", service="ALL", host="ALL", action="deny"}`
- [ ] **端口使用监控** - `linux_security_ports_use_info{process!="unknown"}`

### 4. 系统服务
- [ ] **禁用X Window** - `linux_security_services_info{service_name="xwindow", is_running="false"}`
- [ ] **系统运行级别正确** - `linux_security_system_target_info{current_target="multi-user.target"}`
- [ ] **无运行中的不必要服务** - `count(linux_security_services_info{service_name=~"nfs|cups|bluetooth|avahi-daemon|rpcbind|postfix", is_running="true"}) == 0`

### 5. 系统维护
- [ ] **系统补丁信息** - `linux_security_last_patch_time{package_type!="unknown"}`

## Prometheus告警规则

```yaml
groups:
- name: linux_security_compliance
  rules:
  # 关键安全告警
  - alert: RootSSHLoginEnabled
    expr: linux_security_sshd_config_info{info_key="PermitRootLogin", info_value="yes"}
    for: 0m
    labels:
      severity: critical
      category: security
    annotations:
      summary: "Root SSH direct login is enabled"
      description: "Root account can login directly via SSH, which violates security policy"

  - alert: SELinuxNotEnforcing
    expr: linux_security_selinux_config{info_key="SELINUX", info_value=~"permissive|disabled"}
    for: 0m
    labels:
      severity: warning
      category: security
    annotations:
      summary: "SELinux is not in enforcing mode"
      description: "SELinux should be in enforcing mode for better security"

  - alert: SELinuxDisabled
    expr: linux_security_selinux_config{info_key="SELINUX", info_value="disabled"}
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

  - alert: FirewallNotRunning
    expr: linux_security_firewall_enabled{firewall_type!="none", is_running="false"} == 1
    for: 5m
    labels:
      severity: warning
      category: security
    annotations:
      summary: "Firewall is enabled but not running"
      description: "Firewall {{ $labels.firewall_type }} is enabled but not currently running"

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
    expr: linux_security_login_defs_info{info_key="PASS_MAX_DAYS", info_value="num"} > 90
    for: 0m
    labels:
      severity: warning
      category: password_policy
    annotations:
      summary: "Password max days is too long"
      description: "Password max days should be 90 or fewer days"

  - alert: PasswordMinLengthTooShort
    expr: linux_security_login_defs_info{info_key="PASS_MIN_LEN", info_value="num"} < 10
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
    expr: linux_security_last_patch_time{package_type="unknown"}
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
  (linux_security_sshd_config_info{info_key="PermitRootLogin", info_value="no"} or vector(0)) * 20 +
  (linux_security_selinux_config{info_key="SELINUX", info_value="enforcing"} or vector(0)) * 15 +
  (linux_security_firewall_enabled{firewall_type!="none"} == 1) * 10 +
  (linux_security_firewall_enabled{firewall_type!="none", is_running="true"} == 1) * 5 +
  ((linux_security_login_defs_info{info_key="PASS_MIN_LEN", info_value="num"} >= 10) or vector(0)) * 10 +
  ((linux_security_login_defs_info{info_key="PASS_MAX_DAYS", info_value="num"} <= 90) or vector(0)) * 10 +
  (linux_security_services_info{service_name="xwindow", is_running="false"} or vector(0)) * 5 +
  (count(linux_security_services_info{service_name=~"nfs|cups|bluetooth|avahi-daemon|rpcbind|postfix", is_running="true"}) == 0) * 10 +
  (linux_security_hosts_options_info{file="hosts.deny", service="ALL", host="ALL", action="deny"} or vector(0)) * 5 +
  (linux_security_last_patch_time{package_type!="unknown"} or vector(0)) * 5
)
```

**评分说明**:
- SSH禁用root登录: 20分
- SELinux强制模式: 15分
- 防火墙启用: 10分
- 防火墙正在运行: 5分
- 密码最小长度符合要求: 10分
- 密码最大有效期符合要求: 10分
- 禁用X Window: 5分
- 无不必要服务运行: 10分
- TCP Wrappers配置: 5分
- 系统补丁信息可用: 5分
- **总分**: 100分

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

# 检查防火墙是否正在运行
linux_security_firewall_enabled{is_running="true"}
linux_security_firewall_enabled{firewall_type="firewalld", is_running="true"}

# 检查防火墙已启用但未运行
linux_security_firewall_enabled{firewall_type!="none", is_running="false"} == 1

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

### 系统维护监控

```promql
# 查询补丁时间信息
linux_security_last_patch_time

# 查询包数量信息
linux_security_package_count

# 按包管理器类型统计
linux_security_package_count{package_type="rpm"}
linux_security_package_count{package_type="dpkg"}
linux_security_package_count{package_type="pacman"}

# 查询未知包管理器类型
linux_security_last_patch_time{package_type="unknown"}
linux_security_package_count{package_type="unknown"}
```

### 账户密码策略监控

```promql
# 查看所有账户的密码最大有效期
linux_security_password_max_days

# 查找密码有效期过长的账户
linux_security_password_max_days > 90

# 查看账户过期信息
linux_security_account_expire

# 查看密码警告天数设置
linux_security_password_warn_days

# 查看密码不活跃天数设置
linux_security_password_inactive

# 查看最后密码修改时间
linux_security_last_password_change

# 查看密码最小有效期
linux_security_password_min_days

# 组合查询：查看有sudo权限的账户的密码策略
linux_security_password_max_days * on(username) group_left() linux_security_account_info{has_sudo="true"}

# 统计不同shell的使用情况
count by (shell) (linux_security_account_info)

# 查看有sudo权限的账户
linux_security_account_info{has_sudo="true"}

# 计算密码策略平均值
avg(linux_security_password_max_days)

# 统计密码有效期分布
count by (password_max_days) (linux_security_password_max_days)
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
