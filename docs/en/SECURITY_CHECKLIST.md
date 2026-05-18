[中文](../zh/SECURITY_CHECKLIST.md) | English

# Linux Security Configuration Checklist

Compliance checklist based on Linux security configuration standards.

## Check Items

### 1. Account Management
- [ ] **Create cnet account** - `linux_security_account_info{username="cnet"}`
- [ ] **Disable direct root SSH login** - `linux_security_sshd_config_info{info_key="PermitRootLogin", info_value="no"}`
- [ ] **Remove unnecessary accounts** - Check account information via `linux_security_account_info`
- [ ] **Check account password policy** - Check password expiry via `linux_security_password_max_days`

### 2. Password Policy
- [ ] **Password maximum age 90 days** - `linux_security_login_defs_info{info_key="PASS_MAX_DAYS", info_value="num"} <= 90`
- [ ] **Minimum password length 10 characters** - `linux_security_login_defs_info{info_key="PASS_MIN_LEN", info_value="num"} >= 10`
- [ ] **Password warning period 7 days** - `linux_security_login_defs_info{info_key="PASS_WARN_AGE", info_value="num"} == 7`

### 3. System Security Configuration
- [ ] **SELinux enforcing mode** - `linux_security_selinux_config{info_key="SELINUX", info_value="enforcing"}`
- [ ] **Firewall enabled** - `linux_security_firewall_enabled{firewall_type!="none"} == 1`
- [ ] **Firewall running** - `linux_security_firewall_enabled{firewall_type!="none", is_running="true"} == 1`
- [ ] **TCP Wrappers configured** - `linux_security_hosts_options_info{file="hosts.deny", service="ALL", host="ALL", action="deny"}`
- [ ] **Port usage monitoring** - `linux_security_ports_use_info{process!="unknown"}`

### 4. System Services
- [ ] **X Window disabled** - `linux_security_services_info{service_name="xwindow", is_running="false"}`
- [ ] **Correct system run level** - `linux_security_system_target_info{current_target="multi-user.target"}`
- [ ] **No unnecessary services running** - `count(linux_security_services_info{service_name=~"nfs|cups|bluetooth|avahi-daemon|rpcbind|postfix", is_running="true"}) == 0`

### 5. System Maintenance
- [ ] **System patch information** - `linux_security_last_patch_time{package_type!="unknown"}`
  - Supported package managers: rpm (RedHat/CentOS), dpkg (Debian/Ubuntu), pacman (Arch Linux)
- [ ] **Installed package count** - `linux_security_package_count{package_type!="unknown"}`

## Prometheus Alert Rules

```yaml
groups:
- name: linux_security_compliance
  rules:
  # Critical security alerts
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

  # Password policy alerts
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

  # System configuration alerts
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

  # System maintenance alerts
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

## Compliance Score

You can use the following PromQL query to calculate a system security compliance score:

```promql
# Calculate security compliance score (0-100 points)
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

**Score Breakdown**:
- SSH root login disabled: 20 points
- SELinux enforcing mode: 15 points
- Firewall enabled: 10 points
- Firewall running: 5 points
- Minimum password length compliant: 10 points
- Password maximum age compliant: 10 points
- X Window disabled: 5 points
- No unnecessary services running: 10 points
- TCP Wrappers configured: 5 points
- System patch info available: 5 points
- **Total**: 100 points

## Recommended Check Frequency

- **Real-time monitoring**: Critical security configurations (SELinux, firewall, SSH configuration)
- **Hourly checks**: Service status, account status
- **Daily checks**: Password policy, system patch status
- **Weekly checks**: Full compliance assessment

## Additional Query Examples

### Firewall Type Checks

```promql
# Check specific firewall type (supports firewalld, ufw, iptables, nftables)
linux_security_firewall_enabled{firewall_type="firewalld"}    # RedHat/CentOS 7+
linux_security_firewall_enabled{firewall_type="ufw"}          # Ubuntu/Debian
linux_security_firewall_enabled{firewall_type="iptables"}    # Traditional firewall
linux_security_firewall_enabled{firewall_type="nftables"}     # Modern firewall

# Check if firewall is running
linux_security_firewall_enabled{is_running="true"}
linux_security_firewall_enabled{firewall_type="firewalld", is_running="true"}

# Check firewall enabled but not running
linux_security_firewall_enabled{firewall_type!="none", is_running="false"} == 1

# Check firewall not enabled
linux_security_firewall_enabled{firewall_type="none"} == 1

# Count enabled firewalls
sum(linux_security_firewall_enabled)
```

### Port and Process Monitoring

```promql
# Query port usage by specific process
linux_security_ports_use_info{process="sshd"}
linux_security_ports_use_info{process="nginx"}
linux_security_ports_use_info{process="mysql"}

# Query process using specific port
linux_security_ports_use_info{port="22"}
linux_security_ports_use_info{port="80"}
linux_security_ports_use_info{port="443"}

# Query ports by protocol and state
linux_security_ports_use_info{protocol="tcp", state="LISTEN"}
linux_security_ports_use_info{protocol="tcp", state="ESTABLISHED"}

# Query ports used by specific application (Java apps, etc.)
linux_security_ports_use_info{app_name="elasticsearch"}
linux_security_ports_use_info{app_name="kafka"}

# Query ports with version information
linux_security_ports_use_info{version!=""}

# Count ports per process
count by (process) (linux_security_ports_use_info)

# Count ports per application
count by (app_name) (linux_security_ports_use_info)

# Query ports used by unknown processes
linux_security_ports_use_info{process="unknown"}
```

### Service Status Monitoring

```promql
# Query status of specific services
linux_security_services_info{service_name="sshd"}
linux_security_services_info{service_name="nginx"}

# Query running services
linux_security_services_info{is_running="true"}

# Query enabled services
linux_security_services_info{is_enabled="true"}

# Query by service type (systemd, init, xwindow, wayland)
linux_security_services_info{service_type="systemd"}
linux_security_services_info{service_type="init"}

# Count services by type
count by (service_type) (linux_security_services_info)

# Count running services
count(linux_security_services_info{is_running="true"})

# Query X Window service status (should be disabled on servers)
linux_security_services_info{service_name="xwindow", is_running="true"}
```

### System Maintenance Monitoring

```promql
# Query patch time information
linux_security_last_patch_time

# Query package count information
linux_security_package_count

# Query by package manager type (supports rpm, dpkg, pacman)
linux_security_package_count{package_type="rpm"}      # RedHat/CentOS systems
linux_security_package_count{package_type="dpkg"}     # Debian/Ubuntu systems
linux_security_package_count{package_type="pacman"}   # Arch Linux systems

# Query unknown package manager type (may be unsupported system or configuration issue)
linux_security_last_patch_time{package_type="unknown"}
linux_security_package_count{package_type="unknown"}

# Track package count trends (requires Prometheus query capabilities)
rate(linux_security_package_count[5m])
```

### Account Password Policy Monitoring

```promql
# View password maximum age for all accounts
linux_security_password_max_days

# Find accounts with password expiry too long
linux_security_password_max_days > 90

# View account expiration information
linux_security_account_expire

# View password warning period settings
linux_security_password_warn_days

# View password inactivity period settings
linux_security_password_inactive

# View last password change time
linux_security_last_password_change

# View password minimum age
linux_security_password_min_days

# Combined query: view password policy for accounts with sudo privileges
linux_security_password_max_days * on(username) group_left() linux_security_account_info{has_sudo="true"}

# Count shell usage distribution
count by (shell) (linux_security_account_info)

# View accounts with sudo privileges
linux_security_account_info{has_sudo="true"}

# Calculate average password policy values
avg(linux_security_password_max_days)

# Count password age distribution
count by (password_max_days) (linux_security_password_max_days)
```

## Remediation Recommendations

When security configuration issues are found, refer to the original security standards document for remediation:

1. **Account management issues**: Create cnet account, disable root SSH login
2. **Password policy issues**: Modify `/etc/login.defs` and `/etc/security/pwquality.conf`
3. **SELinux issues**: Modify `/etc/selinux/config` and reboot the system
4. **Firewall issues**: Configure iptables or nftables rules
5. **Service issues**: Disable unnecessary services and X Window
6. **Patch issues**: Run system update commands
7. **Port monitoring**: Identify and manage ports used by unknown processes
