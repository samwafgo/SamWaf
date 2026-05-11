@echo off
setlocal

set "CURDIR=%~dp0"
set "CURDIR=%CURDIR:~0,-1%"

SET CGO_ENABLED=1
SET GOOS=windows
SET GOARCH=amd64
SET GIN_MODE=release

:: ---- Step 1: Build v1.1.0 ----
echo [1/3] Building v1.1.0...
if not exist "%CURDIR%\release\githubci\v1.1.0" mkdir "%CURDIR%\release\githubci\v1.1.0"
go build -ldflags="-X SamWaf/global.GWAF_RELEASE=true -X SamWaf/global.GWAF_RELEASE_VERSION_NAME=20260224 -X SamWaf/global.GWAF_RELEASE_VERSION=v1.1.0 -X SamWaf/global.GUPDATE_VERSION_URL=http://127.0.0.1:8111/ -s -w" -o "%CURDIR%\release\githubci\v1.1.0\SamWaf64.exe" ./cmd/samwaf/main.go
if %ERRORLEVEL% neq 0 ( echo FAILED: v1.1.0 build error & pause & exit /b 1 )
echo OK: release\githubci\v1.1.0\SamWaf64.exe

:: ---- Step 2: Build v1.1.1 ----
echo [2/3] Building v1.1.1...
if not exist "%CURDIR%\release\githubci\v1.1.1" mkdir "%CURDIR%\release\githubci\v1.1.1"
go build -ldflags="-X SamWaf/global.GWAF_RELEASE=true -X SamWaf/global.GWAF_RELEASE_VERSION_NAME=20260224 -X SamWaf/global.GWAF_RELEASE_VERSION=v1.1.1 -X SamWaf/global.GUPDATE_VERSION_URL=http://127.0.0.1:8111/ -s -w" -o "%CURDIR%\release\githubci\v1.1.1\SamWaf64.exe" ./cmd/samwaf/main.go
if %ERRORLEVEL% neq 0 ( echo FAILED: v1.1.1 build error & pause & exit /b 1 )
echo OK: release\githubci\v1.1.1\SamWaf64.exe

:: ---- Step 3: Package v1.1.1 update ----
echo [3/3] Packaging v1.1.1...
"%CURDIR%\setup\go_gen_updatefile\go_gen_updatefile.exe" -desc "local-test-1.1.1" -o "%CURDIR%\release\web\samwaf_update" -platform windows-amd64 "%CURDIR%\release\githubci\v1.1.1\SamWaf64.exe" v1.1.1
if %ERRORLEVEL% neq 0 ( echo FAILED: package error & pause & exit /b 1 )
echo OK: release\web\samwaf_update\v1.1.1\windows-amd64.gz

echo.
echo All done. Start v1.1.0 to test upgrade.
echo.
pause
endlocal
