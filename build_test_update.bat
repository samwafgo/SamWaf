@echo off
setlocal

set "CURDIR=%~dp0"
set "CURDIR=%CURDIR:~0,-1%"
set "TESTDIR=%CURDIR%\release\testupdate"

SET CGO_ENABLED=1
SET GOOS=windows
SET GOARCH=amd64
SET GIN_MODE=release

:: ---- Step 1: Build v1.1.0 ----
echo [1/6] Building v1.1.0...
if not exist "%CURDIR%\release\githubci\v1.1.0" mkdir "%CURDIR%\release\githubci\v1.1.0"
go build -ldflags="-X SamWaf/global.GWAF_RELEASE=true -X SamWaf/global.GWAF_RELEASE_VERSION_NAME=20260224 -X SamWaf/global.GWAF_RELEASE_VERSION=v1.1.0 -X SamWaf/global.GUPDATE_VERSION_URL=http://127.0.0.1:8111/ -s -w" -o "%CURDIR%\release\githubci\v1.1.0\SamWaf64.exe" ./cmd/samwaf/main.go
if %ERRORLEVEL% neq 0 ( echo FAILED: v1.1.0 build error & pause & exit /b 1 )
echo OK: release\githubci\v1.1.0\SamWaf64.exe

:: ---- Step 2: Stop test backend and deploy v1.1.0 ----
echo [2/6] Stopping test backend and deploying v1.1.0...
if not exist "%TESTDIR%" mkdir "%TESTDIR%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$d='%TESTDIR%'; $p=Get-Process -Name SamWaf64 -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($d, 'OrdinalIgnoreCase') }; if ($p) { Write-Host ('stopping ' + $p.Count + ' process(es)'); $p | Stop-Process -Force; Start-Sleep -Milliseconds 1500 } else { Write-Host 'no running process' }"
copy /y "%CURDIR%\release\githubci\v1.1.0\SamWaf64.exe" "%TESTDIR%\SamWaf64.exe" >nul
if %ERRORLEVEL% neq 0 ( echo FAILED: copy to test backend error ^(file locked?^) & pause & exit /b 1 )
echo OK: %TESTDIR%\SamWaf64.exe

:: ---- Step 3: Build v1.1.1 ----
echo [3/6] Building v1.1.1...
if not exist "%CURDIR%\release\githubci\v1.1.1" mkdir "%CURDIR%\release\githubci\v1.1.1"
go build -ldflags="-X SamWaf/global.GWAF_RELEASE=true -X SamWaf/global.GWAF_RELEASE_VERSION_NAME=20260224 -X SamWaf/global.GWAF_RELEASE_VERSION=v1.1.1 -X SamWaf/global.GUPDATE_VERSION_URL=http://127.0.0.1:8111/ -s -w" -o "%CURDIR%\release\githubci\v1.1.1\SamWaf64.exe" ./cmd/samwaf/main.go
if %ERRORLEVEL% neq 0 ( echo FAILED: v1.1.1 build error & pause & exit /b 1 )
echo OK: release\githubci\v1.1.1\SamWaf64.exe

:: ---- Step 4: Package v1.1.1 update ----
echo [4/6] Packaging v1.1.1...
"%CURDIR%\setup\go_gen_updatefile\go_gen_updatefile.exe" -desc "local-test-1.1.1" -o "%CURDIR%\release\web\samwaf_update" -platform windows-amd64 "%CURDIR%\release\githubci\v1.1.1\SamWaf64.exe" v1.1.1
if %ERRORLEVEL% neq 0 ( echo FAILED: package error & pause & exit /b 1 )
echo OK: release\web\samwaf_update\v1.1.1\windows-amd64.gz

:: ---- Step 5: Start test backend service ----
echo [5/6] Starting test backend v1.1.0...
pushd "%TESTDIR%"
.\SamWaf64.exe start
if %ERRORLEVEL% neq 0 ( echo WARN: SamWaf64.exe start failed ^(service not installed or no admin rights?^) & pause )
popd

:: ---- Step 6: Start local update HTTP server ----
echo [6/6] Starting HTTP server...
if not exist "%CURDIR%\release\web" mkdir "%CURDIR%\release\web"
where python >nul 2>nul
if %ERRORLEVEL% neq 0 ( echo FAILED: python not found in PATH & pause & exit /b 1 )

echo.
echo All done. Test backend v1.1.0 is running in %TESTDIR%.
echo.
echo HTTP server started: http://127.0.0.1:8111/
echo Root: %CURDIR%\release\web
echo Press Ctrl+C to stop.
echo.
pushd "%CURDIR%\release\web"
python -m http.server 8111
popd
endlocal
