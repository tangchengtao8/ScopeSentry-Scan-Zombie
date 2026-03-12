# 第一阶段：编译阶段 (使用 Go 环境编译包含 zombie 的扫描器)
FROM golang:1.24-alpine AS builder
RUN apk add --no-cache git gcc musl-dev
WORKDIR /build

# 1. 拷贝依赖定义文件
COPY go.mod go.sum ./

# 2. 拷贝所有本地依赖库 (必须在 go mod download 之前)
# 这些是 go.mod 中 replace 指令指向的本地目录
COPY libs/ ./libs/
COPY internal/zombie ./internal/zombie

# 3. 下载依赖
RUN go mod download

# 4. 拷贝全量源码并编译
COPY . .
RUN go build -o ScopeSentry-Scan cmd/ScopeSentry/main.go

# 第二阶段：运行阶段 (官方原始运行环境)
FROM python:3.7-slim

WORKDIR /apps
COPY msyh.ttc /usr/share/fonts/

# 安装官方要求的依赖
RUN apt-get update && apt-get install -y \
    libexif-dev \
    udev \
    chromium \
    vim \
    tzdata \
    libpcap-dev \
    default-jdk \
    && rm -rf /var/lib/apt/lists/*

RUN pip install uro

# 1. 从编译阶段拷贝生成的新二进制文件
COPY --from=builder /build/ScopeSentry-Scan /apps/ScopeSentry-Scan
RUN chmod +x /apps/ScopeSentry-Scan

# 2. 拷贝并配置内置工具 (保持官方目录结构)
RUN mkdir -p /apps/ext/rad /apps/ext/ksubdomain /apps/ext/rustscan /apps/ext/katana
COPY tools/linux/ksubdomain /apps/ext/ksubdomain/ksubdomain
COPY tools/linux/rad /apps/ext/rad/rad
COPY tools/linux/rustscan /apps/ext/rustscan/rustscan
COPY tools/linux/katana /apps/ext/katana/katana
RUN chmod +x /apps/ext/ksubdomain/ksubdomain /apps/ext/rad/rad /apps/ext/rustscan/rustscan /apps/ext/katana/katana

# 设置时区与编码
RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN echo 'Asia/Shanghai' >/etc/timezone
ENV LANG C.UTF-8

# 启动命令
ENTRYPOINT ["/apps/ScopeSentry-Scan"]