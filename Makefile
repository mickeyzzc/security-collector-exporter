# Security Collector Makefile

.PHONY: build test clean run lint fmt docker-build docker-run docker-push

# 构建变量
BINARY_NAME=security-exporter
BUILD_DIR=bin
MAIN_PATH=./cmd/security-exporter
DOCKER_IMAGE=security-exporter
DOCKER_TAG=latest

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

# Linux 构建
build-linux:
	@echo "Building for Linux..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(MAIN_PATH)

# Docker 构建
docker-build:
	@echo "Building Docker image..."
	@docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

# Docker 运行
docker-run:
	@echo "Running Docker container..."
	@docker run -d --name $(BINARY_NAME) -p 9102:9102 --privileged $(DOCKER_IMAGE):$(DOCKER_TAG)

# Docker 停止
docker-stop:
	@echo "Stopping Docker container..."
	@docker stop $(BINARY_NAME) || true
	@docker rm $(BINARY_NAME) || true

# Docker 推送
docker-push:
	@echo "Pushing Docker image..."
	@docker push $(DOCKER_IMAGE):$(DOCKER_TAG)

# Docker 清理
docker-clean:
	@echo "Cleaning Docker images..."
	@docker rmi $(DOCKER_IMAGE):$(DOCKER_TAG) || true

# 帮助信息
help:
	@echo "Available targets:"
	@echo "  build         - Build the binary"
	@echo "  run           - Run the application"
	@echo "  test          - Run tests"
	@echo "  fmt           - Format code"
	@echo "  lint          - Run linter"
	@echo "  clean         - Clean build files"
	@echo "  deps          - Install dependencies"
	@echo "  build-linux   - Build for Linux"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run Docker container"
	@echo "  docker-stop   - Stop Docker container"
	@echo "  docker-push   - Push Docker image"
	@echo "  docker-clean  - Clean Docker images"
	@echo "  help          - Show this help"
