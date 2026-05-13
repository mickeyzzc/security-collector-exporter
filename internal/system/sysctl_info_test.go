package system

import (
	"testing"
)

func TestSysctlParamInfo_Structure(t *testing.T) {
	info := SysctlParamInfo{
		Name:          "net.ipv4.ip_forward",
		Value:         "0",
		ExpectedValue: "0",
		IsSecure:      true,
	}
	if info.Name != "net.ipv4.ip_forward" {
		t.Errorf("期望 Name 'net.ipv4.ip_forward'，得到 '%s'", info.Name)
	}
	if info.Value != "0" {
		t.Errorf("期望 Value '0'，得到 '%s'", info.Value)
	}
	if info.ExpectedValue != "0" {
		t.Errorf("期望 ExpectedValue '0'，得到 '%s'", info.ExpectedValue)
	}
	if !info.IsSecure {
		t.Error("期望 IsSecure true")
	}
}

func TestSysctlParamInfo_Insecure(t *testing.T) {
	info := SysctlParamInfo{
		Name:          "net.ipv4.ip_forward",
		Value:         "1",
		ExpectedValue: "0",
		IsSecure:      false,
	}
	if info.IsSecure {
		t.Error("期望 IsSecure false")
	}
}

func TestReadSysctlParam_InvalidPath(t *testing.T) {
	result := readSysctlParam("nonexistent.param.xyz")
	if result != "" {
		t.Errorf("不存在的参数应返回空字符串，得到 '%s'", result)
	}
}

func TestGetSysctlSecurityParams_ParamsCount(t *testing.T) {
	t.Skip("需要 /proc/sys/ 访问，跳过")
	params := GetSysctlSecurityParams()
	if len(params) != 7 {
		t.Errorf("期望 7 个参数，得到 %d", len(params))
	}
}

func TestParseSysctlContent(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{"normal value", "0\n", "0"},
		{"value with newline", "1\n", "1"},
		{"value with spaces", " 2 \n", "2"},
		{"empty content", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := parseSysctlContent(tc.content)
			if result != tc.expected {
				t.Errorf("parseSysctlContent(%q) = %q, want %q", tc.content, result, tc.expected)
			}
		})
	}
}
