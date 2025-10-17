package system

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
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
	output, err := exec.Command("groups", username).Output()
	if err != nil {
		return nil, err
	}

	// 输出格式: username : group1 group2 group3
	line := strings.TrimSpace(string(output))
	parts := strings.Split(line, " : ")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid groups output")
	}

	groups := strings.Fields(parts[1])
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
