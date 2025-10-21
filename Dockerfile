# 多阶段构建
FROM golang:1.21-alpine AS builder

# 构建参数
ARG VERSION=dev
ARG GIT_COMMIT=unknown

# 设置工作目录
WORKDIR /app

# 安装必要的包
RUN apk add --no-cache git ca-certificates tzdata

# 复制 go mod 文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X security-exporter/pkg/config.Version=${VERSION:-dev} \
              -X security-exporter/pkg/config.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
              -X security-exporter/pkg/config.GitCommit=${GIT_COMMIT:-unknown} \
              -X security-exporter/pkg/config.GoVersion=$(go version)" \
    -a -installsuffix cgo -o security-exporter ./cmd/security-exporter

# 运行阶段
FROM alpine:latest

# 安装必要的包
RUN apk --no-cache add ca-certificates tzdata

# 创建非root用户
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# 设置工作目录
WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/security-exporter .

# 更改文件所有者
RUN chown -R appuser:appgroup /app

# 切换到非root用户
USER appuser

# 暴露端口
EXPOSE 9102

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9102/metrics || exit 1

# 运行应用
CMD ["./security-exporter"]
