#!/bin/bash

# Simple IP Blocker 插件编译脚本

PLUGIN_NAME="simple_ip_blocker"
OUTPUT_DIR="../../../data/plugins/binaries"

echo "========================================"
echo "编译 Simple IP Blocker 插件"
echo "========================================"

# 创建输出目录
mkdir -p $OUTPUT_DIR

# 编译插件
echo "正在编译..."
go build -o $PLUGIN_NAME

if [ $? -eq 0 ]; then
    echo "✅ 编译成功"
    
    # 复制到运行时目录
    echo "正在复制到运行时目录..."
    cp $PLUGIN_NAME $OUTPUT_DIR/
    
    if [ $? -eq 0 ]; then
        echo "✅ 复制成功: $OUTPUT_DIR/$PLUGIN_NAME"
        
        # 设置执行权限
        chmod +x $OUTPUT_DIR/$PLUGIN_NAME
        
        echo ""
        echo "插件编译完成！"
        echo "二进制位置: $OUTPUT_DIR/$PLUGIN_NAME"
        echo ""
        echo "下一步："
        echo "1. 配置插件（在 conf/plugins.yml 或通过API）"
        echo "2. 启动 SamWaf"
        echo "3. 插件将自动加载并运行"
    else
        echo "❌ 复制失败"
        exit 1
    fi
else
    echo "❌ 编译失败"
    exit 1
fi

echo "========================================"

