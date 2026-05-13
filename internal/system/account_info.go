// Package system 采集 Linux 系统安全相关信息，包括账户、SSH、防火墙、端口、服务等指标。
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
	UID          int
	GID          string
	PrimaryGroup string
	Groups       []string
	HasSudo      bool
}

func parsePasswdContent(content string) []AccountInfo {
	var accounts []AccountInfo
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(parts[2])
		accounts = append(accounts, AccountInfo{
			Username: parts[0],
			UID:      uid,
			GID:      parts[3],
			HomeDir:  parts[5],
			Shell:    parts[6],
		})
	}
	return accounts
}

// GetAllAccountInfo 获取所有账户信息
func GetAllAccountInfo() ([]AccountInfo, error) {
	content, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}

	accounts := parsePasswdContent(string(content))

	for i := range accounts {
		primaryGroup, err := getGroupName(accounts[i].GID)
		if err != nil {
			primaryGroup = "unknown"
		}
		accounts[i].PrimaryGroup = primaryGroup

		groups, err := getUserGroups(accounts[i].Username)
		if err != nil {
			groups = []string{primaryGroup}
		}
		accounts[i].Groups = groups

		hasSudo, err := checkSudoPermission(accounts[i].Username)
		if err != nil {
			hasSudo = false
		}
		accounts[i].HasSudo = hasSudo
	}

	return accounts, nil
}

// getGroupName 根据GID获取组名
func getGroupName(gid string) (string, error) {
	file, err := os.Open("/etc/group")
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

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
	defer func() { _ = file.Close() }()

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
	defer func() { _ = passwdFile.Close() }()

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
		// #nosec G304 -- 采集系统信息需要动态路径
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

func parseShadowContent(content string) []ShadowInfo {
	var shadowInfos []ShadowInfo
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 9 {
			continue
		}
		shadowInfos = append(shadowInfos, ShadowInfo{
			Username:           parts[0],
			LastPasswordChange: parts[2],
			PasswordMinDays:    parts[3],
			PasswordMaxDays:    parts[4],
			PasswordWarnDays:   parts[5],
			PasswordInactive:   parts[6],
			AccountExpire:      parts[7],
		})
	}
	return shadowInfos
}

// GetAllShadowInfo 获取所有用户的shadow信息
func GetAllShadowInfo() ([]ShadowInfo, error) {
	content, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return nil, err
	}

	return parseShadowContent(string(content)), nil
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
	defer func() { _ = file.Close() }()

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
