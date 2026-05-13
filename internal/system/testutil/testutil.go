// Package testutil 提供测试辅助工具函数，用于管理测试数据文件。
package testutil

import (
    "os"
    "path/filepath"
    "testing"
)

// TestdataPath returns the absolute path to a testdata file
func TestdataPath(t *testing.T, relPath string) string {
    t.Helper()
    baseDir := filepath.Join("..", "testdata")
    absPath := filepath.Join(baseDir, relPath)
    if _, err := os.Stat(absPath); os.IsNotExist(err) {
        t.Fatalf("testdata file not found: %s", absPath)
    }
    return absPath
}

// ReadTestdata reads a testdata file and returns its content
func ReadTestdata(t *testing.T, relPath string) string {
    t.Helper()
    path := TestdataPath(t, relPath)
    // #nosec G304 -- 测试辅助函数使用动态路径
    data, err := os.ReadFile(path)
    if err != nil {
        t.Fatalf("failed to read testdata %s: %v", path, err)
    }
    return string(data)
}

// CreateTempFile creates a temporary file with the given content
func CreateTempFile(t *testing.T, content string) string {
    t.Helper()
    f, err := os.CreateTemp("", "test-*.txt")
    if err != nil {
        t.Fatalf("failed to create temp file: %v", err)
    }
    t.Cleanup(func() { _ = os.Remove(f.Name()) })
    _, err = f.WriteString(content)
    if err != nil {
        t.Fatalf("failed to write temp file: %v", err)
    }
    _ = f.Close()
    return f.Name()
}