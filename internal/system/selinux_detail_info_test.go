package system

import (
	"testing"
)

func TestSELinuxDetailInfo_Structure(t *testing.T) {
	info := SELinuxDetailInfo{
		SELinuxMode:      "enforcing",
		SELinuxPolicy:    "targeted",
		AppArmorEnabled:  true,
		AppArmorProfiles: 12,
		AppArmorEnforced: 8,
	}
	if info.SELinuxMode != "enforcing" {
		t.Errorf("期望 SELinuxMode 'enforcing'，得到 '%s'", info.SELinuxMode)
	}
	if info.SELinuxPolicy != "targeted" {
		t.Errorf("期望 SELinuxPolicy 'targeted'，得到 '%s'", info.SELinuxPolicy)
	}
	if !info.AppArmorEnabled {
		t.Error("期望 AppArmorEnabled true")
	}
	if info.AppArmorProfiles != 12 {
		t.Errorf("期望 AppArmorProfiles 12，得到 %d", info.AppArmorProfiles)
	}
	if info.AppArmorEnforced != 8 {
		t.Errorf("期望 AppArmorEnforced 8，得到 %d", info.AppArmorEnforced)
	}
}

func TestParseSELinuxMode(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{"enforcing (1)", "1", "enforcing"},
		{"permissive (0)", "0", "permissive"},
		{"unknown value", "2", ""},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSELinuxModeFromContent(tc.content)
			if got != tc.expected {
				t.Errorf("parseSELinuxModeFromContent(%q) = %q, want %q", tc.content, got, tc.expected)
			}
		})
	}
}

func TestParseSELinuxDetailConfig(t *testing.T) {
	content := `# This file controls the state of SELinux on the system.
SELINUX=enforcing
SELINUXTYPE=targeted
`
	mode := parseSELinuxModeFromConfig(content)
	if mode != "enforcing" {
		t.Errorf("期望 'enforcing'，得到 '%s'", mode)
	}

	policy := parseSELinuxPolicyFromConfig(content)
	if policy != "targeted" {
		t.Errorf("期望 'targeted'，得到 '%s'", policy)
	}
}

func TestParseSELinuxDetailConfig_Disabled(t *testing.T) {
	content := "SELINUX=disabled\nSELINUXTYPE=targeted\n"
	mode := parseSELinuxModeFromConfig(content)
	if mode != "disabled" {
		t.Errorf("期望 'disabled'，得到 '%s'", mode)
	}
}

func TestParseSELinuxDetailConfig_Empty(t *testing.T) {
	mode := parseSELinuxModeFromConfig("")
	if mode != "" {
		t.Errorf("空内容应返回空字符串，得到 '%s'", mode)
	}
}

func TestParseAppArmorStats(t *testing.T) {
	output := `32 profiles are loaded.
24 profiles are in enforce mode.
8 profiles are in complain mode.
0 profiles are in kill mode.`
	profiles, enforced := parseAppArmorStatsFromOutput(output)
	if profiles != 32 {
		t.Errorf("期望 profiles 32，得到 %d", profiles)
	}
	if enforced != 24 {
		t.Errorf("期望 enforced 24，得到 %d", enforced)
	}
}

func TestParseAppArmorStats_Empty(t *testing.T) {
	profiles, enforced := parseAppArmorStatsFromOutput("")
	if profiles != 0 {
		t.Errorf("期望 profiles 0，得到 %d", profiles)
	}
	if enforced != 0 {
		t.Errorf("期望 enforced 0，得到 %d", enforced)
	}
}

func TestGetSELinuxDetailInfo(t *testing.T) {
	t.Skip("需要 /sys/fs/selinux 和系统命令访问，跳过")
	info := GetSELinuxDetailInfo()
	validModes := map[string]bool{"enforcing": true, "permissive": true, "disabled": true, "unknown": true}
	if !validModes[info.SELinuxMode] {
		t.Errorf("SELinuxMode '%s' 不是有效模式", info.SELinuxMode)
	}
}
