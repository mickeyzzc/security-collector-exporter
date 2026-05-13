package system

import (
	"os"
	"testing"
)

func TestGetPatchTimeInfo_NonLinux(t *testing.T) {
	if os.PathSeparator != '/' || !fileExists("/proc") {
		t.Skip("requires Linux")
	}
	info, err := GetPatchTimeInfo()
	if err != nil {
		t.Fatalf("GetPatchTimeInfo() error: %v", err)
	}
	if info == nil {
		t.Fatal("GetPatchTimeInfo() returned nil")
	}
}

func TestGetPackageCountInfo_NonLinux(t *testing.T) {
	if os.PathSeparator != '/' || !fileExists("/proc") {
		t.Skip("requires Linux")
	}
	info, err := GetPackageCountInfo()
	if err != nil {
		t.Fatalf("GetPackageCountInfo() error: %v", err)
	}
	if info == nil {
		t.Fatal("GetPackageCountInfo() returned nil")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
