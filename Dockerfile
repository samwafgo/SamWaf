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

# 复制 release/SamWafLinux64 到镜像中
COPY dist/samwaf_linux_linux_amd64_v1/SamWafLinux64 ./SamWafLinux64

# 设置执行权限
RUN chmod +x SamWafLinux64

# 挂载 conf, data, logs 和 ssl 目录
VOLUME ["/app/conf", "/app/data", "/app/logs", "/app/ssl"]

# 暴露端口
EXPOSE 26666 80 443

# 设置默认命令来启动 SamWafLinux64
CMD ["./SamWafLinux64"]