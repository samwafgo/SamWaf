@echo off
REM Simple IP Blocker 插件编译脚本 (Windows)

SET PLUGIN_NAME=simple_ip_blocker.exe
SET OUTPUT_DIR=..\..\..\data\plugins\binaries

echo ========================================
echo 编译 Simple IP Blocker 插件
echo ========================================

REM 创建输出目录
if not exist %OUTPUT_DIR% mkdir %OUTPUT_DIR%

REM 编译插件
echo 正在编译...
go build -o %PLUGIN_NAME%

if %ERRORLEVEL% EQU 0 (
    echo ✅ 编译成功
    
    REM 复制到运行时目录
    echo 正在复制到运行时目录...
    copy /Y %PLUGIN_NAME% %OUTPUT_DIR%\
    
    if %ERRORLEVEL% EQU 0 (
        echo ✅ 复制成功: %OUTPUT_DIR%\%PLUGIN_NAME%
        echo.
        echo 插件编译完成！
        echo 二进制位置: %OUTPUT_DIR%\%PLUGIN_NAME%
        echo.
        echo 下一步：
        echo 1. 配置插件（在 conf/plugins.yml 或通过API）
        echo 2. 启动 SamWaf
        echo 3. 插件将自动加载并运行
    ) else (
        echo ❌ 复制失败
        exit /b 1
    )
) else (
    echo ❌ 编译失败
    exit /b 1
)

echo ========================================
pause

