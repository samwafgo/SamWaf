# 构建阶段包含 CGO 工具链；SQLite 仅用于旧数据迁移，因此仍需 C 编译器。
FROM golang:1.25.9-alpine AS build
RUN apk add --no-cache build-base bash curl git
WORKDIR /src
# 先缓存依赖，再复制源码，避免每次注释/源码修改都重新下载依赖。
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# 控制台前端由独立仓库发布，按仓库配置获取产物后再嵌入；兼容 Windows 检出的 CRLF 脚本。
RUN sed -i 's/\r$//' .github/scripts/fetch_web_dist.sh && bash .github/scripts/fetch_web_dist.sh
ENV CGO_ENABLED=1 GOAMD64=v1 CGO_CFLAGS="-Wno-unused-variable -D_LARGEFILE64_SOURCE"
RUN go build -trimpath -ldflags="-s -w" -o /out/SamWafLinux64 ./cmd/samwaf

# 运行镜像只带应用及必要运行依赖，编译器和构建目录不进入最终镜像。
FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata iptables
WORKDIR /app
COPY --from=build /out/SamWafLinux64 /app/SamWafLinux64
ENV TZ=Asia/Shanghai
# data 中同时包含实例密钥和持久 L2，升级容器时必须沿用同一数据挂载。
VOLUME ["/app/conf", "/app/data", "/app/logs", "/app/ssl"]
EXPOSE 26666 80 443
ENTRYPOINT ["/app/SamWafLinux64"]
