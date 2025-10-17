package system

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// BoolToFloat64 将bool转换为float64
func BoolToFloat64(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

// isProcessRunning 检查进程是否在运行
func isProcessRunning(processName string) bool {
	// 读取/proc目录获取所有进程
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// 检查是否为数字目录（进程ID）
		pid := entry.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}

		// 读取进程命令行
		cmdlinePath := fmt.Sprintf("/proc/%s/cmdline", pid)
		if content, err := os.ReadFile(cmdlinePath); err == nil {
			cmdline := string(content)
			// 检查命令行是否包含进程名
			if strings.Contains(cmdline, processName) {
				return true
			}
		}
	}

	return false
}

// getProcessByInode 通过inode获取进程名
func getProcessByInode(line string) string {
	// 解析行格式获取inode
	parts := strings.Fields(line)
	if len(parts) < 10 {
		return "unknown"
	}

	// inode是最后一个字段
	inode := parts[len(parts)-1]
	if inode == "" {
		return "unknown"
	}

	// 扫描所有进程目录查找匹配的inode
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return "unknown"
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// 检查是否为数字目录（进程ID）
		pid := entry.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}

		// 检查进程的fd目录
		fdDir := fmt.Sprintf("/proc/%s/fd", pid)
		if fdEntries, err := os.ReadDir(fdDir); err == nil {
			for _, fdEntry := range fdEntries {
				// 读取符号链接目标
				linkPath := fmt.Sprintf("/proc/%s/fd/%s", pid, fdEntry.Name())
				if target, err := os.Readlink(linkPath); err == nil {
					// 检查是否匹配socket inode
					if strings.Contains(target, fmt.Sprintf("socket:[%s]", inode)) {
						// 获取进程名
						return getProcessName(pid)
					}
				}
			}
		}
	}

	return "unknown"
}

// getProcessName 获取进程名
func getProcessName(pid string) string {
	// 读取进程状态文件
	statusPath := fmt.Sprintf("/proc/%s/status", pid)
	if content, err := os.ReadFile(statusPath); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Name:") {
				name := strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
				return name
			}
		}
	}

	// 如果无法读取status文件，尝试读取comm文件
	commPath := fmt.Sprintf("/proc/%s/comm", pid)
	if content, err := os.ReadFile(commPath); err == nil {
		return strings.TrimSpace(string(content))
	}

	return "unknown"
}
