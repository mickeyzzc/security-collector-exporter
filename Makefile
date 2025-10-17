# Security Collector Makefile

.PHONY: build test clean run lint fmt

# 构建变量
BINARY_NAME=security-exporter
BUILD_DIR=bin
MAIN_PATH=./cmd/security-exporter

# 默认目标
all: fmt lint test build

# 构建
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)
	@echo "Build completed: $(BUILD_DIR)/$(BINARY_NAME)"

# 运行
run:
	@echo "Running $(BINARY_NAME)..."
	@go run $(MAIN_PATH)

# 测试
test:
	@echo "Running tests..."
	@go test -v ./...

# 代码格式化
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# 代码检查
lint:
	@echo "Running linter..."
	@go vet ./...

# 清理构建文件
clean:
	@echo "Cleaning build files..."
	@rm -rf $(BUILD_DIR)

# 安装依赖
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy

# 交叉编译
build-linux:
	@echo "Building for Linux..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(MAIN_PATH)

build-windows:
	@echo "Building for Windows..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(MAIN_PATH)

build-darwin:
	@echo "Building for macOS..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(MAIN_PATH)

# 构建所有平台
build-all: build-linux build-windows build-darwin

# 帮助信息
help:
	@echo "Available targets:"
	@echo "  build      - Build the binary"
	@echo "  run        - Run the application"
	@echo "  test       - Run tests"
	@echo "  fmt        - Format code"
	@echo "  lint       - Run linter"
	@echo "  clean      - Clean build files"
	@echo "  deps       - Install dependencies"
	@echo "  build-all  - Build for all platforms"
	@echo "  help       - Show this help"
