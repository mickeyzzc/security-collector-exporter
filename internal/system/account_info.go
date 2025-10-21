package system

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// AccountInfo 账户信息结构
type AccountInfo struct {
	Username     string
	HomeDir      string
	Shell        string
	PrimaryGroup string
	Groups       []string
	HasSudo      bool
}

// GetAllAccountInfo 获取所有账户信息
func GetAllAccountInfo() ([]AccountInfo, error) {
	var accounts []AccountInfo

	// 读取passwd文件
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析passwd行: username:password:uid:gid:gecos:home:shell
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}

		username := parts[0]
		homeDir := parts[5]
		shell := parts[6]

		// 获取主组名
		primaryGroup, err := getGroupName(parts[3])
		if err != nil {
			primaryGroup = "unknown"
		}

		// 获取所有组
		groups, err := getUserGroups(username)
		if err != nil {
			groups = []string{primaryGroup}
		}

		// 检查sudo权限
		hasSudo, err := checkSudoPermission(username)
		if err != nil {
			hasSudo = false
		}

		accounts = append(accounts, AccountInfo{
			Username:     username,
			HomeDir:      homeDir,
			Shell:        shell,
			PrimaryGroup: primaryGroup,
			Groups:       groups,
			HasSudo:      hasSudo,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return accounts, nil
}

// getGroupName 根据GID获取组名
func getGroupName(gid string) (string, error) {
	file, err := os.Open("/etc/group")
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析group行: groupname:password:gid:members
		parts := strings.Split(line, ":")
		if len(parts) >= 3 && parts[2] == gid {
			return parts[0], nil
		}
	}

	return "unknown", nil
}

// getUserGroups 获取用户的所有组
func getUserGroups(username string) ([]string, error) {
	var groups []string

	// 1. 从 /etc/group 文件中查找用户所属的组
	file, err := os.Open("/etc/group")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析group行: groupname:password:gid:members
		parts := strings.Split(line, ":")
		if len(parts) >= 4 {
			groupName := parts[0]
			members := parts[3]

			// 检查用户是否在该组的成员列表中
			if members != "" {
				memberList := strings.Split(members, ",")
				for _, member := range memberList {
					if strings.TrimSpace(member) == username {
						groups = append(groups, groupName)
						break
					}
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// 2. 从 /etc/passwd 文件中获取用户的主组
	passwdFile, err := os.Open("/etc/passwd")
	if err != nil {
		return groups, nil // 如果无法读取passwd文件，返回已找到的组
	}
	defer passwdFile.Close()

	passwdScanner := bufio.NewScanner(passwdFile)
	for passwdScanner.Scan() {
		line := passwdScanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析passwd行: username:password:uid:gid:gecos:home:shell
		parts := strings.Split(line, ":")
		if len(parts) >= 4 && parts[0] == username {
			// 获取主组名
			primaryGroup, err := getGroupName(parts[3])
			if err == nil && primaryGroup != "unknown" {
				// 检查主组是否已经在列表中
				found := false
				for _, group := range groups {
					if group == primaryGroup {
						found = true
						break
					}
				}
				if !found {
					groups = append(groups, primaryGroup)
				}
			}
			break
		}
	}

	return groups, nil
}

// checkSudoPermission 检查用户是否有sudo权限
func checkSudoPermission(username string) (bool, error) {
	// 检查sudoers文件
	sudoersPaths := []string{
		"/etc/sudoers",
		"/etc/sudoers.d/" + username,
	}

	for _, path := range sudoersPaths {
		if _, err := os.Stat(path); err == nil {
			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				// 检查是否包含该用户的sudo规则
				if strings.Contains(line, username) &&
					(strings.Contains(line, "ALL") || strings.Contains(line, "NOPASSWD")) {
					return true, nil
				}
			}
		}
	}

	// 检查用户是否在sudo组中
	groups, err := getUserGroups(username)
	if err != nil {
		return false, err
	}

	for _, group := range groups {
		if group == "sudo" || group == "wheel" {
			return true, nil
		}
	}

	return false, nil
}

// ShadowInfo shadow文件信息结构
type ShadowInfo struct {
	Username           string
	LastPasswordChange string
	PasswordMaxDays    string
	PasswordMinDays    string
	PasswordWarnDays   string
	PasswordInactive   string
	AccountExpire      string
}

// ShadowMetrics 拆分的shadow指标结构
type ShadowMetrics struct {
	LastPasswordChange []ShadowMetric
	PasswordMaxDays    []ShadowMetric
	PasswordMinDays    []ShadowMetric
	PasswordWarnDays   []ShadowMetric
	PasswordInactive   []ShadowMetric
	AccountExpire      []ShadowMetric
}

// ShadowMetric 单个shadow指标
type ShadowMetric struct {
	Username string
	Value    float64
}

// GetAllShadowInfo 获取所有用户的shadow信息
func GetAllShadowInfo() ([]ShadowInfo, error) {
	var shadowInfos []ShadowInfo

	// 读取shadow文件
	file, err := os.Open("/etc/shadow")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析shadow行: username:password:lastchange:min:max:warn:inactive:expire:reserved
		parts := strings.Split(line, ":")
		if len(parts) < 9 {
			continue
		}

		username := parts[0]
		// 跳过密码字段（索引1），只获取其他信息
		shadowInfo := ShadowInfo{
			Username:           username,
			LastPasswordChange: parts[2], // 最后密码修改时间
			PasswordMinDays:    parts[3], // 密码最小有效期
			PasswordMaxDays:    parts[4], // 密码最大有效期
			PasswordWarnDays:   parts[5], // 密码警告天数
			PasswordInactive:   parts[6], // 密码不活跃天数
			AccountExpire:      parts[7], // 账户过期时间
		}

		shadowInfos = append(shadowInfos, shadowInfo)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return shadowInfos, nil
}

// GetAllShadowMetrics 获取拆分的shadow指标
func GetAllShadowMetrics() (*ShadowMetrics, error) {
	metrics := &ShadowMetrics{
		LastPasswordChange: []ShadowMetric{},
		PasswordMaxDays:    []ShadowMetric{},
		PasswordMinDays:    []ShadowMetric{},
		PasswordWarnDays:   []ShadowMetric{},
		PasswordInactive:   []ShadowMetric{},
		AccountExpire:      []ShadowMetric{},
	}

	// 读取shadow文件
	file, err := os.Open("/etc/shadow")
	if err != nil {
		return metrics, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析shadow行: username:password:lastchange:min:max:warn:inactive:expire:reserved
		parts := strings.Split(line, ":")
		if len(parts) < 9 {
			continue
		}

		username := parts[0]

		// 解析各个字段的数值
		lastChange := parseShadowValue(parts[2])
		maxDays := parseShadowValue(parts[4])
		minDays := parseShadowValue(parts[3])
		warnDays := parseShadowValue(parts[5])
		inactive := parseShadowValue(parts[6])
		expire := parseShadowValue(parts[7])

		// 添加到对应的指标中
		if lastChange >= 0 {
			metrics.LastPasswordChange = append(metrics.LastPasswordChange, ShadowMetric{
				Username: username,
				Value:    lastChange,
			})
		}

		if maxDays >= 0 {
			metrics.PasswordMaxDays = append(metrics.PasswordMaxDays, ShadowMetric{
				Username: username,
				Value:    maxDays,
			})
		}

		if minDays >= 0 {
			metrics.PasswordMinDays = append(metrics.PasswordMinDays, ShadowMetric{
				Username: username,
				Value:    minDays,
			})
		}

		if warnDays >= 0 {
			metrics.PasswordWarnDays = append(metrics.PasswordWarnDays, ShadowMetric{
				Username: username,
				Value:    warnDays,
			})
		}

		if inactive >= 0 {
			metrics.PasswordInactive = append(metrics.PasswordInactive, ShadowMetric{
				Username: username,
				Value:    inactive,
			})
		}

		if expire >= 0 {
			metrics.AccountExpire = append(metrics.AccountExpire, ShadowMetric{
				Username: username,
				Value:    expire,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return metrics, err
	}

	return metrics, nil
}

// parseShadowValue 解析shadow字段值
func parseShadowValue(value string) float64 {
	// 空值或特殊值返回-1表示无效
	if value == "" || value == "0" || value == "99999" {
		return -1
	}

	// 尝试转换为数字
	if val, err := strconv.ParseFloat(value, 64); err == nil {
		return val
	}

	return -1
}
