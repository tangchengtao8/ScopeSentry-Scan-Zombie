
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

# 拷贝当前目录下的可执行文件到容器中
# 注意：这需要您先在本机或通过其他方式获得编译好的 ScopeSentry-Scan 二进制文件
# 如果您没有编译环境，建议直接使用官方镜像
COPY dist/ScopeSentry-Scan_linux_amd64_v1/ScopeSentry-Scan /apps/ScopeSentry-Scan
RUN chmod +x /apps/ScopeSentry-Scan

# 创建工具目录并拷贝官方内置工具 (包括您放入的 zombie)
RUN mkdir -p /apps/ext/rad /apps/ext/ksubdomain /apps/ext/rustscan /apps/ext/katana
COPY tools/linux/ksubdomain /apps/ext/ksubdomain/ksubdomain
COPY tools/linux/rad /apps/ext/rad/rad
COPY tools/linux/rustscan /apps/ext/rustscan/rustscan
COPY tools/linux/katana /apps/ext/katana/katana
# 只要您把 zombie 放在 tools/linux/zombie，这里就会拷贝进去
COPY tools/linux/zombie /apps/ext/zombie
RUN chmod +x /apps/ext/ksubdomain/ksubdomain /apps/ext/rad/rad /apps/ext/rustscan/rustscan /apps/ext/katana/katana /apps/ext/zombie

# 设置时区与编码
RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN echo 'Asia/Shanghai' >/etc/timezone
ENV LANG C.UTF-8

ENTRYPOINT ["/apps/ScopeSentry-Scan"]
