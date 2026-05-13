package system

import (
	"os"
	"testing"
)

func TestGetAllServicesInfo_NonLinux(t *testing.T) {
	if os.PathSeparator != '/' || !fileExists("/proc") {
		t.Skip("requires Linux")
	}
	services, err := GetAllServicesInfo()
	if err != nil {
		t.Fatalf("GetAllServicesInfo() error: %v", err)
	}
	if services == nil {
		t.Fatal("GetAllServicesInfo() returned nil")
	}
}
