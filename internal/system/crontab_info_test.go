package system

import (
	"testing"
)

func TestIsValidTimeField(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"0", true},
		{"*", true},
		{"*/5", true},
		{"1-30", true},
		{"1,15", true},
		{"*/30", true},
		{"", false},
		{"abc", false},
		{"MON", false},
		{"root", false},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := isValidTimeField(tc.input)
			if got != tc.expected {
				t.Errorf("isValidTimeField(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}

func TestParseCrontabLine_System(t *testing.T) {
	line := "0 5 * * 1 root /usr/bin/backup.sh"
	entry, ok := parseCrontabLine(line, "/etc/crontab", true)
	if !ok {
		t.Fatal("期望成功解析系统crontab行")
	}
	if entry.User != "root" {
		t.Errorf("期望 User 'root'，得到 '%s'", entry.User)
	}
	if entry.Command != "/usr/bin/backup.sh" {
		t.Errorf("期望 Command '/usr/bin/backup.sh'，得到 '%s'", entry.Command)
	}
	if entry.Source != "/etc/crontab" {
		t.Errorf("期望 Source '/etc/crontab'，得到 '%s'", entry.Source)
	}
	if !entry.IsSystem {
		t.Error("期望 IsSystem true")
	}
	if entry.Schedule != "0 5 * * 1" {
		t.Errorf("期望 Schedule '0 5 * * 1'，得到 '%s'", entry.Schedule)
	}
}

func TestParseCrontabLine_User(t *testing.T) {
	line := "*/30 * * * * /home/user/script.sh"
	entry, ok := parseCrontabLine(line, "/var/spool/cron/user", false)
	if !ok {
		t.Fatal("期望成功解析用户crontab行")
	}
	if entry.User != "user" {
		t.Errorf("期望 User 'user'（从文件名推断），得到 '%s'", entry.User)
	}
	if entry.Command != "/home/user/script.sh" {
		t.Errorf("期望 Command '/home/user/script.sh'，得到 '%s'", entry.Command)
	}
	if entry.IsSystem {
		t.Error("期望 IsSystem false")
	}
}

func TestParseCrontabLine_Comment(t *testing.T) {
	_, ok := parseCrontabLine("# this is a comment", "/etc/crontab", true)
	if ok {
		t.Error("注释行应被跳过")
	}
}

func TestParseCrontabLine_Empty(t *testing.T) {
	_, ok := parseCrontabLine("", "/etc/crontab", true)
	if ok {
		t.Error("空行应被跳过")
	}
}

func TestParseCrontabLine_ShortLine(t *testing.T) {
	_, ok := parseCrontabLine("0 5 * * 1", "/etc/crontab", true)
	if ok {
		t.Error("字段不足的系统crontab行应被跳过")
	}
}

func TestParseCrontabLine_EnvVar(t *testing.T) {
	_, ok := parseCrontabLine("SHELL=/bin/bash", "/etc/crontab", true)
	if ok {
		t.Error("环境变量行应被跳过")
	}
}

func TestGetAllCrontabInfo(t *testing.T) {
	t.Skip("需要 /etc/crontab 和 /var/spool/cron 访问，跳过")
	entries := GetAllCrontabInfo()
	if entries == nil {
		t.Error("结果不应为 nil")
	}
}
