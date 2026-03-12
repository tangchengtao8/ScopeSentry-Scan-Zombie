
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
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN pip install uro

# 拷贝当前目录下的可执行文件到容器中
# 注意：这需要您先在本机或通过其他方式获得编译好的 ScopeSentry-Scan 二进制文件
COPY dist/ScopeSentry-Scan_linux_amd64_v1/ScopeSentry-Scan /apps/ScopeSentry-Scan
RUN chmod +x /apps/ScopeSentry-Scan

# 1. 自动化获取 zombie 工具 (不再需要手动上传)
RUN mkdir -p /apps/ext && \
    wget https://github.com/chainreactors/zombie/releases/latest/download/zombie_linux_amd64 -O /apps/ext/zombie && \
    chmod +x /apps/ext/zombie

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

ENTRYPOINT ["/apps/ScopeSentry-Scan"]
