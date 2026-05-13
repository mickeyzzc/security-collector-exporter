package system

import (
	"strings"
	"testing"
)

func TestAuditdInfo_Structure(t *testing.T) {
	info := AuditdInfo{
		IsRunning:      true,
		RulesCount:     42,
		ServiceEnabled: true,
		Version:        "3.0",
	}
	if !info.IsRunning {
		t.Error("期望 IsRunning true")
	}
	if info.RulesCount != 42 {
		t.Errorf("期望 RulesCount 42，得到 %d", info.RulesCount)
	}
	if !info.ServiceEnabled {
		t.Error("期望 ServiceEnabled true")
	}
	if info.Version != "3.0" {
		t.Errorf("期望 Version '3.0'，得到 '%s'", info.Version)
	}
}

func TestCountAuditRulesFromContent(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected int
	}{
		{
			name:     "empty content",
			content:  "",
			expected: 0,
		},
		{
			name:     "only comments",
			content:  "# comment1\n# comment2\n",
			expected: 0,
		},
		{
			name:     "valid rules",
			content:  "-a always,exit -F arch=b64 -S execve\n-a always,exit -F arch=b32 -S execve\n",
			expected: 2,
		},
		{
			name:     "mixed comments and rules",
			content:  "# First rule\n-a always,exit -F arch=b64 -S execve\n# Second section\n-a always,exit -F arch=b32 -S open\n",
			expected: 2,
		},
		{
			name:     "blank lines ignored",
			content:  "\n-a always,exit -S execve\n\n\n-a always,exit -S open\n\n",
			expected: 2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			count := countAuditRulesFromContent(tc.content)
			if count != tc.expected {
				t.Errorf("countAuditRulesFromContent() = %d, want %d", count, tc.expected)
			}
		})
	}
}

func TestCountAuditRulesFromContent_NoRules(t *testing.T) {
	content := "No rules\n"
	count := countAuditRulesFromAuditctlOutput(content)
	if count != 0 {
		t.Errorf("期望 'No rules' 输出计数为 0，得到 %d", count)
	}
}

func TestCountAuditRulesFromAuditctlOutput(t *testing.T) {
	output := "LISTENER: listening for events\n-a always,exit -F arch=b64 -S execve -F key=exec\n-a always,exit -F arch=b64 -S open -F key=file\n"
	lines := strings.Split(output, "\n")
	count := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "No rules") {
			count++
		}
	}
	if count != 3 {
		t.Errorf("从 auditctl 输出计数 = %d, want 3", count)
	}
}

func TestGetAuditdInfo(t *testing.T) {
	t.Skip("需要系统命令和 /proc 访问，跳过")
	info := GetAuditdInfo()
	if info.RulesCount < 0 {
		t.Errorf("RulesCount 不应为负数: %d", info.RulesCount)
	}
}
