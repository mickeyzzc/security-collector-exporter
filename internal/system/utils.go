package system

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"security-exporter/pkg/logger"
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
	logger.Debug("getProcessByInode: 开始解析行: %s", line)

	// 解析行格式获取inode
	parts := strings.Fields(line)
	if len(parts) < 10 {
		logger.Debug("getProcessByInode: 行字段数量不足，只有 %d 个字段", len(parts))
		return "unknown"
	}

	// 通过第一列判断inode位置
	// 第一列格式: "0:", "1:", "2:" 等
	// 如果第一列以数字+冒号结尾，说明是数据行
	var inode string
	if strings.HasSuffix(parts[0], ":") {
		// 数据行：inode是第10个字段（索引9）
		if len(parts) >= 10 {
			inode = parts[9]
		}
	} else {
		// 可能是表头行或其他格式，尝试最后一个字段
		inode = parts[len(parts)-1]
	}
	if inode == "" {
		logger.Debug("getProcessByInode: inode为空")
		return "unknown"
	}

	logger.Debug("getProcessByInode: 提取到inode: %s", inode)

	// 扫描所有进程目录查找匹配的inode
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		logger.Debug("getProcessByInode: 无法读取/proc目录: %v", err)
		return "unknown"
	}

	logger.Debug("getProcessByInode: 找到 %d 个进程目录", len(entries))
	checkedProcesses := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// 检查是否为数字目录（进程ID）
		pid := entry.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}

		checkedProcesses++
		if checkedProcesses%100 == 0 {
			logger.Debug("getProcessByInode: 已检查 %d 个进程", checkedProcesses)
		}

		// 检查进程的fd目录
		fdDir := fmt.Sprintf("/proc/%s/fd", pid)
		if fdEntries, err := os.ReadDir(fdDir); err == nil {
			for _, fdEntry := range fdEntries {
				// 读取符号链接目标
				linkPath := fmt.Sprintf("/proc/%s/fd/%s", pid, fdEntry.Name())
				if target, err := os.Readlink(linkPath); err == nil {
					// 检查是否匹配socket inode
					socketPattern := fmt.Sprintf("socket:[%s]", inode)
					if strings.Contains(target, socketPattern) {
						processName := getProcessName(pid)
						logger.Debug("getProcessByInode: 找到匹配进程 PID=%s, 进程名=%s, socket=%s", pid, processName, target)
						return processName
					}
				}
			}
		}
	}

	logger.Debug("getProcessByInode: 未找到匹配inode %s 的进程，共检查了 %d 个进程", inode, checkedProcesses)
	return "unknown"
}

// getProcessName 获取进程名
func getProcessName(pid string) string {
	logger.Debug("getProcessName: 开始获取PID %s 的进程名", pid)

	// 读取进程状态文件
	statusPath := fmt.Sprintf("/proc/%s/status", pid)
	if content, err := os.ReadFile(statusPath); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Name:") {
				name := strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
				logger.Debug("getProcessName: 从status文件获取到进程名: %s", name)
				return name
			}
		}
	} else {
		logger.Debug("getProcessName: 无法读取status文件 %s: %v", statusPath, err)
	}

	// 如果无法读取status文件，尝试读取comm文件
	commPath := fmt.Sprintf("/proc/%s/comm", pid)
	if content, err := os.ReadFile(commPath); err == nil {
		name := strings.TrimSpace(string(content))
		logger.Debug("getProcessName: 从comm文件获取到进程名: %s", name)
		return name
	} else {
		logger.Debug("getProcessName: 无法读取comm文件 %s: %v", commPath, err)
	}

	logger.Debug("getProcessName: 无法获取PID %s 的进程名", pid)
	return "unknown"
}

// ProcessDetail 进程详细信息（内部使用）
type ProcessDetail struct {
	PID     string
	Name    string
	ExePath string
	CmdLine string
}

// getProcessDetail 获取进程详细信息
func getProcessDetail(pid string) *ProcessDetail {
	logger.Debug("getProcessDetail: 开始获取PID %s 的详细信息", pid)

	detail := &ProcessDetail{
		PID: pid,
	}

	// 获取进程名
	detail.Name = getProcessName(pid)

	// 获取可执行文件路径
	exePath := fmt.Sprintf("/proc/%s/exe", pid)
	if target, err := os.Readlink(exePath); err == nil {
		detail.ExePath = target
		logger.Debug("getProcessDetail: 获取到可执行文件路径: %s", target)
	} else {
		logger.Debug("getProcessDetail: 无法读取可执行文件路径: %v", err)
	}

	// 获取命令行（可选，用于版本号获取）
	cmdlinePath := fmt.Sprintf("/proc/%s/cmdline", pid)
	if content, err := os.ReadFile(cmdlinePath); err == nil {
		detail.CmdLine = strings.ReplaceAll(string(content), "\x00", " ")
		logger.Debug("getProcessDetail: 获取到命令行: %s", detail.CmdLine)
	}

	return detail
}

// getProcessDetailByInode 通过inode获取进程详细信息（内部使用）
func getProcessDetailByInode(line string) *ProcessDetail {
	logger.Debug("getProcessDetailByInode: 开始解析行: %s", line)

	// 解析行格式获取inode
	parts := strings.Fields(line)
	if len(parts) < 10 {
		logger.Debug("getProcessDetailByInode: 行字段数量不足，只有 %d 个字段", len(parts))
		return nil
	}

	// 通过第一列判断inode位置
	var inode string
	if strings.HasSuffix(parts[0], ":") {
		// 数据行：inode是第10个字段（索引9）
		if len(parts) >= 10 {
			inode = parts[9]
		}
	} else {
		// 可能是表头行或其他格式，尝试最后一个字段
		inode = parts[len(parts)-1]
	}
	if inode == "" {
		logger.Debug("getProcessDetailByInode: inode为空")
		return nil
	}

	logger.Debug("getProcessDetailByInode: 提取到inode: %s", inode)

	// 扫描所有进程目录查找匹配的inode
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		logger.Debug("getProcessDetailByInode: 无法读取/proc目录: %v", err)
		return nil
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
					socketPattern := fmt.Sprintf("socket:[%s]", inode)
					if strings.Contains(target, socketPattern) {
						// 找到匹配的进程，返回详细信息
						detail := getProcessDetail(pid)
						if detail != nil {
							logger.Debug("getProcessDetailByInode: 找到匹配进程 PID=%s, 进程名=%s", pid, detail.Name)
						}
						return detail
					}
				}
			}
		}
	}

	logger.Debug("getProcessDetailByInode: 未找到匹配inode %s 的进程", inode)
	return nil
}
