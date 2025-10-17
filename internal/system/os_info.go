package system

import (
	"os"
	"strings"
)

// OSVersionInfo 操作系统版本信息结构
type OSVersionInfo struct {
	PrettyName    string
	Name          string
	Version       string
	VersionID     string
	ID            string
	IDLike        string
	HomeURL       string
	BugReportURL  string
	SupportURL    string
	Variant       string
	VariantID     string
	CPEName       string
	BuildID       string
	ImageID       string
	ImageVersion  string
	RedHatRelease string
}

// GetOSVersionInfo 获取操作系统版本详细信息
func GetOSVersionInfo() (*OSVersionInfo, error) {
	info := &OSVersionInfo{}

	// 检查是否为RedHat系
	if _, err := os.Stat("/etc/redhat-release"); err == nil {
		content, err := os.ReadFile("/etc/redhat-release")
		if err != nil {
			return nil, err
		}
		info.RedHatRelease = strings.TrimSpace(string(content))
	}

	// 检查os-release文件
	if _, err := os.Stat("/etc/os-release"); err == nil {
		content, err := os.ReadFile("/etc/os-release")
		if err != nil {
			return nil, err
		}

		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}

			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			// 移除引号
			if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'')) {
				value = value[1 : len(value)-1]
			}

			switch key {
			case "PRETTY_NAME":
				info.PrettyName = value
			case "NAME":
				info.Name = value
			case "VERSION":
				info.Version = value
			case "VERSION_ID":
				info.VersionID = value
			case "ID":
				info.ID = value
			case "ID_LIKE":
				info.IDLike = value
			case "HOME_URL":
				info.HomeURL = value
			case "BUG_REPORT_URL":
				info.BugReportURL = value
			case "SUPPORT_URL":
				info.SupportURL = value
			case "VARIANT":
				info.Variant = value
			case "VARIANT_ID":
				info.VariantID = value
			case "CPE_NAME":
				info.CPEName = value
			case "BUILD_ID":
				info.BuildID = value
			case "IMAGE_ID":
				info.ImageID = value
			case "IMAGE_VERSION":
				info.ImageVersion = value
			}
		}
	}

	// 如果没有获取到任何信息，设置默认值
	if info.PrettyName == "" && info.RedHatRelease == "" {
		info.PrettyName = "unknown"
	}

	return info, nil
}

// GetOSVersion 获取操作系统版本（保持向后兼容）
func GetOSVersion() (string, error) {
	info, err := GetOSVersionInfo()
	if err != nil {
		return "", err
	}

	if info.PrettyName != "" {
		return info.PrettyName, nil
	}
	if info.RedHatRelease != "" {
		return info.RedHatRelease, nil
	}

	return "unknown", nil
}
