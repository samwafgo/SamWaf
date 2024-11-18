FROM alpine:latest
LABEL authors="samwaf"
# 设置工作目录
WORKDIR /app

# 设置默认时区为上海
ENV TZ=Asia/Shanghai

# 更新并安装时区数据
RUN apk update && \
    apk add --no-cache tzdata && \
    ln -sf /usr/share/zoneinfo/${TZ} /etc/localtime && \
    echo "${TZ}" > /etc/timezone

# 定义构建参数（由 Buildx 提供）
ARG TARGETARCH

# 根据架构动态复制对应的二进制文件
# 只包含当前架构的文件
ADD dist/samwaf_linux_linux_amd64_v1/SamWafLinux64 /app/SamWafLinux64.amd64
ADD dist/samwaf_linux_arm64_linux_arm64/SamWafLinuxArm64 /app/SamWafLinux64.arm64

# 动态选择文件
RUN if [ "${TARGETARCH}" = "amd64" ]; then \
        mv /app/SamWafLinux64.amd64 /app/SamWafLinux64 && rm -f /app/SamWafLinux64.arm64; \
    elif [ "${TARGETARCH}" = "arm64" ]; then \
        mv /app/SamWafLinux64.arm64 /app/SamWafLinux64 && rm -f /app/SamWafLinux64.amd64; \
    else \
        echo "Unsupported architecture: ${TARGETARCH}" && exit 1; \
    fi

# 设置执行权限
RUN chmod +x /app/SamWafLinux64

# 挂载 conf, data, logs 和 ssl 目录
VOLUME ["/app/conf", "/app/data", "/app/logs", "/app/ssl"]

# 暴露端口
EXPOSE 26666 80 443

# 设置默认命令来启动 SamWafLinux64
CMD ["./SamWafLinux64"]