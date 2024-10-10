FROM alpine:latest
LABEL authors="samwaf"
# 设置工作目录
WORKDIR /app

# 复制 release/SamWafLinux64 到镜像中
COPY release/SamWafLinux64 .

# 设置执行权限
RUN chmod +x SamWafLinux64

# 挂载 conf, data,  logs 和ssl 目录
VOLUME ["/app/conf", "/app/data", "/app/logs", "/app/ssl"]

# 暴露端口
EXPOSE 26666 80 443

# 设置默认命令来启动 SamWafLinux64
CMD ["./SamWafLinux64"]