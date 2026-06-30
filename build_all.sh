#!/bin/bash

# 定义输出目录
OUTPUT_DIR="$(pwd)/release"

# 创建输出目录
mkdir -p "$OUTPUT_DIR"

## 编译 Windows 版本
#export CGO_ENABLED=1
#export GOOS=windows
#export GOARCH=amd64
#export GIN_MODE=release
#go build -ldflags="-X SamWaf/global.GWAF_RELEASE=true -X SamWaf/global.GWAF_RELEASE_VERSION_NAME=20240925 -X SamWaf/global.GWAF_RELEASE_VERSION=v1.3.3 -s -w" -o "$OUTPUT_DIR/SamWaf64.exe" main.go
#
## 编译 Linux 版本 (适用于 Debian 和 Ubuntu)
#export GOOS=linux
#export GOARCH=amd64
#go build -ldflags="-X SamWaf/global.GWAF_RELEASE=true -X SamWaf/global.GWAF_RELEASE_VERSION_NAME=20240925 -X SamWaf/global.GWAF_RELEASE_VERSION=v1.3.3 -s -w" -o "$OUTPUT_DIR/SamWaf_linux" main.go

# 编译 macOS 版本 (Intel)
export GOOS=darwin
export GOARCH=amd64
go build -ldflags="-X SamWaf/global.GWAF_RELEASE=true -X SamWaf/global.GWAF_RELEASE_VERSION_NAME=20240925 -X SamWaf/global.GWAF_RELEASE_VERSION=v1.3.3 -s -w" -o "$OUTPUT_DIR/SamWaf_macos_intel" main.go

# 编译 macOS 版本 (ARM, M1/M2)
export GOARCH=arm64
go build -ldflags="-X SamWaf/global.GWAF_RELEASE=true -X SamWaf/global.GWAF_RELEASE_VERSION_NAME=20240925 -X SamWaf/global.GWAF_RELEASE_VERSION=v1.3.3 -s -w" -o "$OUTPUT_DIR/SamWaf_macos_arm" main.go

echo "编译完成，所有可执行文件已生成在 $OUTPUT_DIR 目录中。"