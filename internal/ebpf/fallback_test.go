package ebpf

import (
	"strings"
	"testing"
)

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		wantMajor int
		wantMinor int
		wantErr   bool
	}{
		{
			name:      "标准版本",
			version:   "5.15.0-91-generic",
			wantMajor: 5,
			wantMinor: 15,
		},
		{
			name:      "最低支持版本",
			version:   "5.4.0",
			wantMajor: 5,
			wantMinor: 4,
		},
		{
			name:      "高版本",
			version:   "6.1.0-rc5",
			wantMajor: 6,
			wantMinor: 1,
		},
		{
			name:      "带短横线后缀",
			version:   "5.10-rc1",
			wantMajor: 5,
			wantMinor: 10,
		},
		{
			name:    "缺少次版本号",
			version: "5",
			wantErr: true,
		},
		{
			name:    "空字符串",
			version: "",
			wantErr: true,
		},
		{
			name:    "非法主版本",
			version: "abc.1.0",
			wantErr: true,
		},
		{
			name:    "非法次版本",
			version: "5.xyz.0",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			major, minor, err := parseKernelVersion(tt.version)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseKernelVersion(%q) error = %v, wantErr %v", tt.version, err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if major != tt.wantMajor {
				t.Errorf("parseKernelVersion(%q) major = %d, want %d", tt.version, major, tt.wantMajor)
			}
			if minor != tt.wantMinor {
				t.Errorf("parseKernelVersion(%q) minor = %d, want %d", tt.version, minor, tt.wantMinor)
			}
		})
	}
}

func TestCheckKernelVersion_TooOld(t *testing.T) {
	// 保存原始函数引用，通过直接测试 parseKernelVersion 间接验证
	// 内核版本低于 5.4 应判定为太旧
	oldVersions := []string{"4.19.0", "5.3.0", "3.10.0"}
	for _, v := range oldVersions {
		major, minor, _ := parseKernelVersion(v)
		if major < 5 || (major == 5 && minor < 4) {
			// 符合预期：旧版本
		} else {
			t.Errorf("kernel version %s should be considered too old (parsed as %d.%d)", v, major, minor)
		}
	}
}

func TestCheckBPFAvailability(t *testing.T) {
	// macOS 开发环境预期不可用（/proc 不存在）
	result := CheckBPFAvailability()

	// 在非 Linux 环境上，至少应该报告不可用
	// 且有具体的不可用原因
	if !result.Available {
		if len(result.Reasons) == 0 {
			t.Error("CheckBPFAvailability() returned not available but with no reasons")
		}
		t.Logf("BPF not available (expected on non-Linux): %s", strings.Join(result.Reasons, "; "))
	} else {
		t.Log("BPF available - running on supported Linux with root")
	}
}

func TestBPFAvailability_Reasons(t *testing.T) {
	result := CheckBPFAvailability()

	if result.Available {
		t.Log("BPF available, no reasons to check")
		return
	}

	// 验证每个 reason 都非空
	for i, r := range result.Reasons {
		if r == "" {
			t.Errorf("reason[%d] is empty", i)
		}
		t.Logf("reason[%d]: %s", i, r)
	}

	// 在 macOS 上至少应该包含内核版本检测失败的原因
	foundKernelOrBTF := false
	for _, r := range result.Reasons {
		if strings.Contains(r, "kernel") || strings.Contains(r, "BTF") || strings.Contains(r, "privileges") {
			foundKernelOrBTF = true
			break
		}
	}
	if !foundKernelOrBTF {
		t.Errorf("expected at least one reason mentioning kernel/BTF/privileges, got: %v", result.Reasons)
	}
}

func TestReadUTSRelease(t *testing.T) {
	_, err := readUTSRelease()
	if err != nil {
		// macOS 上预期失败
		t.Logf("readUTSRelease() failed as expected on non-Linux: %v", err)
	} else {
		t.Log("readUTSRelease() succeeded - running on Linux")
	}
}
