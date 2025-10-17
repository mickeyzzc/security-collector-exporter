package system

import (
	"bufio"
	"os"
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
