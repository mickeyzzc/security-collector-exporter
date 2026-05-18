package ebpf

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// BPFAvailability BPF 可用性检查结果
type BPFAvailability struct {
	Available bool
	Reasons   []string // 不可用原因列表
}

// CheckBPFAvailability 检测当前环境是否支持 eBPF
// 返回检查结果和具体原因
func CheckBPFAvailability() BPFAvailability {
	result := BPFAvailability{
		Available: true,
	}

	// 1. 检查 BTF 支持
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		result.Available = false
		result.Reasons = append(result.Reasons, "BTF not available: /sys/kernel/btf/vmlinux not found")
	}

	// 2. 检查内核版本
	if ok, reason := checkKernelVersion(); !ok {
		result.Available = false
		result.Reasons = append(result.Reasons, reason)
	}

	// 3. 检查权限（是否有 CAP_SYS_ADMIN 或 root）
	if os.Geteuid() != 0 {
		result.Available = false
		result.Reasons = append(result.Reasons, fmt.Sprintf("insufficient privileges: running as UID %d, need root or CAP_BPF", os.Geteuid()))
	}

	return result
}

// checkKernelVersion 检查内核版本是否满足最低要求（5.4+）
func checkKernelVersion() (bool, string) {
	uname, err := readUTSRelease()
	if err != nil {
		return false, fmt.Sprintf("cannot determine kernel version: %v", err)
	}

	major, minor, err := parseKernelVersion(uname)
	if err != nil {
		return false, fmt.Sprintf("cannot parse kernel version %q: %v", uname, err)
	}

	// 最低要求: 5.4
	if major < 5 || (major == 5 && minor < 4) {
		return false, fmt.Sprintf("kernel version %d.%d too old, need 5.4+", major, minor)
	}

	return true, ""
}

// readUTSRelease 读取内核版本字符串
func readUTSRelease() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// parseKernelVersion 解析内核版本字符串 "5.15.0-xxx" → (5, 15, nil)
func parseKernelVersion(version string) (int, int, error) {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("invalid version format")
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid major version: %q", parts[0])
	}

	// minor 可能包含 "-xxx" 后缀
	minorStr := strings.SplitN(parts[1], "-", 2)[0]
	minor, err := strconv.Atoi(minorStr)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid minor version: %q", parts[1])
	}

	return major, minor, nil
}
