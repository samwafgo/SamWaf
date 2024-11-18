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

# 复制适用架构的二进制文件到镜像
ARG TARGETARCH
RUN echo "Building for architecture: ${TARGETARCH}"
# 使用RUN指令和if语句根据架构选择文件
RUN if [ "${TARGETARCH}" = "amd64" ]; then \
        cp dist/samwaf_linux_linux_amd64_v1/SamWafLinux64 ./SamWafLinux64; \
    elif [ "${TARGETARCH}" = "arm64" ]; then \
        cp dist/samwaf_linux_arm64_linux_arm64/SamWafLinuxArm64 ./SamWafLinux64; \
    else \
        echo "Unknown architecture: ${TARGETARCH}" && exit 1; \
    fi

# 设置执行权限
RUN chmod +x SamWafLinux64

# 挂载 conf, data, logs 和 ssl 目录
VOLUME ["/app/conf", "/app/data", "/app/logs", "/app/ssl"]

# 暴露端口
EXPOSE 26666 80 443

# 设置默认命令来启动 SamWafLinux64
CMD ["./SamWafLinux64"]