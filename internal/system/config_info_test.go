package system

import (
	"os"
	"testing"
)

func TestParseSSHConfig(t *testing.T) {
	content, err := os.ReadFile("testdata/etc/ssh/sshd_config")
	if err != nil {
		t.Fatalf("读取测试数据失败: %v", err)
	}

	configs := parseSSHConfig(string(content))

	expected := []SSHConfigInfo{
		{Key: "PermitRootLogin", Value: "yes"},
		{Key: "PasswordAuthentication", Value: "yes"},
		{Key: "PubkeyAuthentication", Value: "yes"},
		{Key: "Port", Value: "22"},
		{Key: "AllowUsers", Value: "admin"},
	}

	if len(configs) != len(expected) {
		t.Fatalf("期望 %d 个配置项，得到 %d", len(expected), len(configs))
	}

	for i, exp := range expected {
		if configs[i].Key != exp.Key {
			t.Errorf("配置项 %d: 期望 Key '%s'，得到 '%s'", i, exp.Key, configs[i].Key)
		}
		if configs[i].Value != exp.Value {
			t.Errorf("配置项 %d (%s): 期望 Value '%s'，得到 '%s'", i, exp.Key, exp.Value, configs[i].Value)
		}
	}
}

func TestParseSSHConfig_Empty(t *testing.T) {
	configs := parseSSHConfig("")
	if len(configs) != 0 {
		t.Errorf("空内容应返回空切片，得到 %d 个配置项", len(configs))
	}
}

func TestParseSSHConfig_Comments(t *testing.T) {
	content := "# comment\nPort 22\n\n#PermitRootLogin no\nPasswordAuthentication yes\n"
	configs := parseSSHConfig(content)
	if len(configs) != 2 {
		t.Fatalf("期望 2 个配置项（跳过注释和空行），得到 %d", len(configs))
	}
	if configs[0].Key != "Port" || configs[0].Value != "22" {
		t.Errorf("第一个配置项应为 Port 22，得到 %s=%s", configs[0].Key, configs[0].Value)
	}
}

func TestParseLoginDefs(t *testing.T) {
	content, err := os.ReadFile("testdata/etc/login.defs")
	if err != nil {
		t.Fatalf("读取测试数据失败: %v", err)
	}

	configs := parseLoginDefs(string(content))

	expectedKeys := []string{
		"PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_WARN_AGE",
		"UID_MIN", "UID_MAX", "GID_MIN", "GID_MAX", "NEWPASS_MAX_DAYS",
	}

	if len(configs) != len(expectedKeys) {
		t.Fatalf("期望 %d 个配置项，得到 %d", len(expectedKeys), len(configs))
	}

	for i, key := range expectedKeys {
		if configs[i].Key != key {
			t.Errorf("配置项 %d: 期望 Key '%s'，得到 '%s'", i, key, configs[i].Key)
		}
	}

	// 验证数字值
	if !configs[0].IsNumeric {
		t.Error("PASS_MAX_DAYS 应为数字类型")
	}
	if configs[0].NumValue != 90 {
		t.Errorf("PASS_MAX_DAYS 应为 90，得到 %.0f", configs[0].NumValue)
	}
	if configs[0].Value != "num" {
		t.Errorf("数字类型 Value 应为 'num'，得到 '%s'", configs[0].Value)
	}

	// 验证 PASS_MIN_DAYS
	if configs[1].NumValue != 7 {
		t.Errorf("PASS_MIN_DAYS 应为 7，得到 %.0f", configs[1].NumValue)
	}
}

func TestParseLoginDefs_Empty(t *testing.T) {
	configs := parseLoginDefs("")
	if len(configs) != 0 {
		t.Errorf("空内容应返回空切片，得到 %d 个配置项", len(configs))
	}
}

func TestParseLoginDefs_NonNumeric(t *testing.T) {
	content := "SOME_KEY non_numeric_value\n"
	configs := parseLoginDefs(content)
	if len(configs) != 1 {
		t.Fatalf("期望 1 个配置项，得到 %d", len(configs))
	}
	if configs[0].IsNumeric {
		t.Error("非数字值 IsNumeric 应为 false")
	}
	if configs[0].Value != "non_numeric_value" {
		t.Errorf("Value 应为 'non_numeric_value'，得到 '%s'", configs[0].Value)
	}
}

func TestParseSELinuxConfig(t *testing.T) {
	content, err := os.ReadFile("testdata/etc/selinux/config")
	if err != nil {
		t.Fatalf("读取测试数据失败: %v", err)
	}

	configs := parseSELinuxConfig(string(content))

	if len(configs) != 2 {
		t.Fatalf("期望 2 个配置项，得到 %d", len(configs))
	}

	if configs[0].Key != "SELINUX" {
		t.Errorf("期望 Key 'SELINUX'，得到 '%s'", configs[0].Key)
	}
	if configs[0].Value != "enforcing" {
		t.Errorf("期望 Value 'enforcing'，得到 '%s'", configs[0].Value)
	}

	if configs[1].Key != "SELINUXTYPE" {
		t.Errorf("期望 Key 'SELINUXTYPE'，得到 '%s'", configs[1].Key)
	}
	if configs[1].Value != "targeted" {
		t.Errorf("期望 Value 'targeted'，得到 '%s'", configs[1].Value)
	}
}

func TestParseSELinuxConfig_Empty(t *testing.T) {
	configs := parseSELinuxConfig("")
	if len(configs) != 0 {
		t.Errorf("空内容应返回空切片，得到 %d 个配置项", len(configs))
	}
}

func TestParseSELinuxConfig_Comments(t *testing.T) {
	content := "# comment\nSELINUX=permissive\n\n# another comment\nSELINUXTYPE=minimum\n"
	configs := parseSELinuxConfig(content)
	if len(configs) != 2 {
		t.Fatalf("期望 2 个配置项，得到 %d", len(configs))
	}
}

func TestParseHostsFile(t *testing.T) {
	// 测试 hosts.deny
	denyContent, err := os.ReadFile("testdata/etc/hosts.deny")
	if err != nil {
		t.Fatalf("读取 hosts.deny 测试数据失败: %v", err)
	}
	denyOptions := parseHostsFile(denyContent, "hosts.deny", "deny")

	if len(denyOptions) != 1 {
		t.Fatalf("hosts.deny 期望 1 个条目，得到 %d", len(denyOptions))
	}
	if denyOptions[0].Service != "ALL" {
		t.Errorf("期望 Service 'ALL'，得到 '%s'", denyOptions[0].Service)
	}
	if denyOptions[0].Host != "ALL" {
		t.Errorf("期望 Host 'ALL'，得到 '%s'", denyOptions[0].Host)
	}
	if denyOptions[0].Action != "deny" {
		t.Errorf("期望 Action 'deny'，得到 '%s'", denyOptions[0].Action)
	}

	// 测试 hosts.allow
	allowContent, err := os.ReadFile("testdata/etc/hosts.allow")
	if err != nil {
		t.Fatalf("读取 hosts.allow 测试数据失败: %v", err)
	}
	allowOptions := parseHostsFile(allowContent, "hosts.allow", "allow")

	if len(allowOptions) != 2 {
		t.Fatalf("hosts.allow 期望 2 个条目，得到 %d", len(allowOptions))
	}
	if allowOptions[0].Service != "sshd" {
		t.Errorf("期望 Service 'sshd'，得到 '%s'", allowOptions[0].Service)
	}
	if allowOptions[0].Host != "10.0.0.0/8 : allow" {
		t.Errorf("期望 Host '10.0.0.0/8 : allow'，得到 '%s'", allowOptions[0].Host)
	}
}

func TestParseHostsFile_Empty(t *testing.T) {
	options := parseHostsFile([]byte(""), "hosts.deny", "deny")
	if len(options) != 0 {
		t.Errorf("空内容应返回空切片，得到 %d 个条目", len(options))
	}
}

func TestParseHostsFile_Comments(t *testing.T) {
	content := []byte("# comment\nsshd: 10.0.0.1\n\nALL: ALL\n")
	options := parseHostsFile(content, "hosts.allow", "allow")
	if len(options) != 2 {
		t.Fatalf("期望 2 个条目（跳过注释和空行），得到 %d", len(options))
	}
}
