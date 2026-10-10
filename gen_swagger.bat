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
echo [信息] 开始生成 Swagger 文档（仅 swagger.json）...
echo.

:: --outputTypes json 只生成 swagger.json，不生成 docs.go / swagger.yaml
"%SWAG_EXE%" init ^
    -g cmd/samwaf/main.go ^
    -o docs/openapi ^
    --outputTypes json ^
    --parseDependency ^
    --parseInternal

if not %errorlevel% == 0 (
    echo.
    echo [失败] 文档生成过程中出现错误，请检查上方日志
    pause
    exit /b 1
)

:: 清理旧版脚本遗留的多余输出（本脚本只保留 swagger.json）
if exist "docs\openapi\docs.go" del /q "docs\openapi\docs.go"
if exist "docs\openapi\swagger.yaml" del /q "docs\openapi\swagger.yaml"

echo.
echo [成功] 已生成 docs/openapi/swagger.json

:: 同步到 SamWafDoc 文档站（swagger UI 静态资源）
set "SAMWAFDOC_SWAGGER=C:\huawei\goproject\SamWafDoc\docs\.vuepress\public\swagger.json"
if exist "C:\huawei\goproject\SamWafDoc\docs\.vuepress\public\" (
    copy /y "docs\openapi\swagger.json" "%SAMWAFDOC_SWAGGER%" >nul
    if not %errorlevel% == 0 (
        echo [警告] 同步 swagger.json 到 SamWafDoc 失败，请手动复制
    ) else (
        echo [成功] 已同步到 %SAMWAFDOC_SWAGGER%
    )
) else (
    echo [警告] 未找到 SamWafDoc 目录: C:\huawei\goproject\SamWafDoc，跳过同步
)

echo.
echo ============================================
echo  接口路由测试（需 SamWaf 已在本机运行）
echo ============================================
echo.

go test -v -run TestAllRoutes ./test/apicheck/
if not %errorlevel% == 0 (
    echo.
    echo [失败] 接口路由测试未通过，请检查上方日志
    pause
    exit /b 1
)

echo.
echo [成功] 接口路由测试通过
echo.
echo [全部完成] swagger.json 已生成并同步，接口测试通过
echo.
pause
