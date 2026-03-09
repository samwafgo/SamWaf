@echo off
chcp 65001 >nul
echo ============================================
echo  SamWaf Swagger 文档生成脚本
echo ============================================
echo.

:: 切换到脚本所在目录（项目根目录）
cd /d "%~dp0"

:: 查找 swag.exe 路径（优先 GOPATH/bin，其次 PATH）
set SWAG_EXE=
if exist "%GOPATH%\bin\swag.exe" (
    set SWAG_EXE=%GOPATH%\bin\swag.exe
) else if exist "%USERPROFILE%\go\bin\swag.exe" (
    set SWAG_EXE=%USERPROFILE%\go\bin\swag.exe
) else (
    where swag >nul 2>&1
    if %errorlevel% == 0 (
        set SWAG_EXE=swag
    )
)

if "%SWAG_EXE%"=="" (
    echo [错误] 未找到 swag.exe，请先执行以下命令安装：
    echo   go install github.com/swaggo/swag/cmd/swag@latest
    echo.
    pause
    exit /b 1
)

echo [信息] 使用 swag: %SWAG_EXE%
echo [信息] 开始生成 Swagger 文档...
echo.

"%SWAG_EXE%" init ^
    -g cmd/samwaf/main.go ^
    -o docs/openapi ^
    --parseDependency ^
    --parseInternal

if %errorlevel% == 0 (
    echo.
    echo [成功] Swagger 文档已生成至 docs/openapi/
    echo   - docs/openapi/docs.go
    echo   - docs/openapi/swagger.json
    echo   - docs/openapi/swagger.yaml
) else (
    echo.
    echo [失败] 文档生成过程中出现错误，请检查上方日志
)

echo.
pause
