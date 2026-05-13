package system

import (
	"os"
	"testing"
)

func TestParsePasswdContent(t *testing.T) {
	content, err := os.ReadFile("testdata/etc/passwd")
	if err != nil {
		t.Fatalf("读取测试数据失败: %v", err)
	}

	accounts := parsePasswdContent(string(content))

	if len(accounts) != 5 {
		t.Fatalf("期望 5 个条目，得到 %d", len(accounts))
	}

	// 验证 root
	if accounts[0].Username != "root" {
		t.Errorf("期望用户名 'root'，得到 '%s'", accounts[0].Username)
	}
	if accounts[0].Shell != "/bin/bash" {
		t.Errorf("期望 Shell '/bin/bash'，得到 '%s'", accounts[0].Shell)
	}
	if accounts[0].UID != 0 {
		t.Errorf("期望 UID 0，得到 %d", accounts[0].UID)
	}
	if accounts[0].HomeDir != "/root" {
		t.Errorf("期望 HomeDir '/root'，得到 '%s'", accounts[0].HomeDir)
	}

	// 验证 admin (UID 1000)
	if accounts[2].Username != "admin" {
		t.Errorf("期望用户名 'admin'，得到 '%s'", accounts[2].Username)
	}
	if accounts[2].UID != 1000 {
		t.Errorf("期望 UID 1000，得到 %d", accounts[2].UID)
	}
	if accounts[2].HomeDir != "/home/admin" {
		t.Errorf("期望 HomeDir '/home/admin'，得到 '%s'", accounts[2].HomeDir)
	}

	// 验证 mysql (shell=/bin/false)
	if accounts[3].Username != "mysql" {
		t.Errorf("期望用户名 'mysql'，得到 '%s'", accounts[3].Username)
	}
	if accounts[3].Shell != "/bin/false" {
		t.Errorf("期望 Shell '/bin/false'，得到 '%s'", accounts[3].Shell)
	}

	// 验证 nobody (UID 65534)
	if accounts[4].UID != 65534 {
		t.Errorf("期望 UID 65534，得到 %d", accounts[4].UID)
	}
}

func TestParsePasswdContent_Empty(t *testing.T) {
	accounts := parsePasswdContent("")
	if len(accounts) != 0 {
		t.Errorf("空内容应返回空切片，得到 %d 个条目", len(accounts))
	}
}

func TestParsePasswdContent_Comments(t *testing.T) {
	content := "# comment line\nroot:x:0:0:root:/root:/bin/bash\n\n"
	accounts := parsePasswdContent(content)
	if len(accounts) != 1 {
		t.Fatalf("期望 1 个条目（跳过注释和空行），得到 %d", len(accounts))
	}
	if accounts[0].Username != "root" {
		t.Errorf("期望用户名 'root'，得到 '%s'", accounts[0].Username)
	}
}

func TestParsePasswdContent_InvalidLines(t *testing.T) {
	content := "invalid_line\nroot:x:0:0:root:/root:/bin/bash\nalso:invalid"
	accounts := parsePasswdContent(content)
	if len(accounts) != 1 {
		t.Fatalf("期望 1 个有效条目，得到 %d", len(accounts))
	}
}

func TestParseShadowContent(t *testing.T) {
	content, err := os.ReadFile("testdata/etc/shadow")
	if err != nil {
		t.Fatalf("读取测试数据失败: %v", err)
	}

	shadows := parseShadowContent(string(content))

	if len(shadows) != 5 {
		t.Fatalf("期望 5 个条目，得到 %d", len(shadows))
	}

	// 验证 root
	if shadows[0].Username != "root" {
		t.Errorf("期望用户名 'root'，得到 '%s'", shadows[0].Username)
	}
	if shadows[0].LastPasswordChange != "19000" {
		t.Errorf("期望 LastPasswordChange '19000'，得到 '%s'", shadows[0].LastPasswordChange)
	}
	if shadows[0].PasswordMaxDays != "99999" {
		t.Errorf("期望 PasswordMaxDays '99999'，得到 '%s'", shadows[0].PasswordMaxDays)
	}
	if shadows[0].PasswordWarnDays != "7" {
		t.Errorf("期望 PasswordWarnDays '7'，得到 '%s'", shadows[0].PasswordWarnDays)
	}

	// 验证 admin (LastPasswordChange=19500)
	if shadows[1].Username != "admin" {
		t.Errorf("期望用户名 'admin'，得到 '%s'", shadows[1].Username)
	}
	if shadows[1].LastPasswordChange != "19500" {
		t.Errorf("期望 LastPasswordChange '19500'，得到 '%s'", shadows[1].LastPasswordChange)
	}

	// 验证 nobody（字段不完整但>=9个冒号分隔）
	if shadows[4].Username != "nobody" {
		t.Errorf("期望用户名 'nobody'，得到 '%s'", shadows[4].Username)
	}
}

func TestParseShadowContent_Empty(t *testing.T) {
	shadows := parseShadowContent("")
	if len(shadows) != 0 {
		t.Errorf("空内容应返回空切片，得到 %d 个条目", len(shadows))
	}
}

func TestParseShadowContent_Comments(t *testing.T) {
	content := "# comment\nroot:$6$hash:19000:0:99999:7:::\n\n"
	shadows := parseShadowContent(content)
	if len(shadows) != 1 {
		t.Fatalf("期望 1 个条目，得到 %d", len(shadows))
	}
	if shadows[0].Username != "root" {
		t.Errorf("期望用户名 'root'，得到 '%s'", shadows[0].Username)
	}
}
