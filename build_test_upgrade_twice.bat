@echo off
setlocal

:: =====================================================================
:: Reproduce the Windows self-update "Access is denied" bug.
::
:: Why build_test_update.bat can NOT reproduce it:
::   that script kills every SamWaf64 process and overwrites the exe on
::   EVERY run, so the test dir is always clean (no leftover .old, no
::   long-lived old Supervisor). It only ever exercises the FIRST upgrade.
::
:: The bug needs TWO upgrades in a row with NO process kill in between:
::   upgrade #1 renames SamWaf64.exe -> .SamWaf64.exe.old and succeeds,
::   but the Supervisor never exits, so its running image IS that .old
::   file and it can never be deleted (Windows). Upgrade #2 then tries to
::   rename onto that still-in-use .old and gets ERROR_ACCESS_DENIED.
::
:: This script prepares the ground and then gets out of the way: it
:: publishes ONLY v1.1.1 so upgrade #1 is a real single step. Publish
:: v1.1.2 later with publish_test_version.bat to trigger upgrade #2.
:: =====================================================================

set "CURDIR=%~dp0"
set "CURDIR=%CURDIR:~0,-1%"
set "TESTDIR=%CURDIR%\release\testupdate"
set "WEBDIR=%CURDIR%\release\web"
set "GENTOOL=%CURDIR%\setup\go_gen_updatefile\go_gen_updatefile.exe"
set "VERNAME=20260224"
set "UPURL=http://127.0.0.1:8111/"

SET CGO_ENABLED=1
SET GOOS=windows
SET GOARCH=amd64
SET GIN_MODE=release

:: ---- Step 1: Build v1.1.0 / v1.1.1 / v1.1.2 ----
echo [1/6] Building v1.1.0, v1.1.1, v1.1.2...
call :build v1.1.0 || exit /b 1
call :build v1.1.1 || exit /b 1
call :build v1.1.2 || exit /b 1

:: ---- Step 2: Stop test backend, wipe leftovers, deploy v1.1.0 ----
:: This is the ONLY point where processes are killed. After this the test
:: must run untouched, otherwise the bug cannot surface.
echo [2/6] Stopping test backend, cleaning leftovers, deploying v1.1.0...
if not exist "%TESTDIR%" mkdir "%TESTDIR%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$d='%TESTDIR%'; $p=Get-Process -Name SamWaf64 -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($d, 'OrdinalIgnoreCase') }; if ($p) { Write-Host ('stopping ' + $p.Count + ' process(es)'); $p | Stop-Process -Force; Start-Sleep -Milliseconds 1500 } else { Write-Host 'no running process' }"

:: Wipe .SamWaf64.exe.old / .new left by earlier runs so the test starts
:: from a genuinely clean state (they are HIDDEN, so -Force is required).
powershell -NoProfile -ExecutionPolicy Bypass -Command "$d='%TESTDIR%'; $f=Get-ChildItem -Force -LiteralPath $d -Filter '.SamWaf64.exe.*' -ErrorAction SilentlyContinue; if ($f) { foreach ($i in $f) { try { $i.Attributes='Normal'; Remove-Item -Force -LiteralPath $i.FullName -ErrorAction Stop; Write-Host ('wiped ' + $i.Name) } catch { Write-Host ('CANNOT WIPE ' + $i.Name + ' -> ' + $_.Exception.Message); Write-Host 'A process is still holding it. Stop it and re-run this script.'; exit 1 } } } else { Write-Host 'no leftover .old/.new' }"
if %ERRORLEVEL% neq 0 ( echo FAILED: leftover cleanup & pause & exit /b 1 )

copy /y "%CURDIR%\release\githubci\v1.1.0\SamWaf64.exe" "%TESTDIR%\SamWaf64.exe" >nul
if %ERRORLEVEL% neq 0 ( echo FAILED: copy to test backend error ^(file locked?^) & pause & exit /b 1 )
echo OK: %TESTDIR%\SamWaf64.exe is v1.1.0

:: ---- Step 3: Publish ONLY v1.1.1 ----
:: windows-amd64.json holds a single target version, so publishing v1.1.2
:: now would make v1.1.0 jump straight to v1.1.2 and skip the two-step.
echo [3/6] Publishing v1.1.1 to the local update server...
call :publish v1.1.1 || exit /b 1

:: ---- Step 4: Start test backend ----
echo [4/6] Starting test backend v1.1.0...
pushd "%TESTDIR%"
.\SamWaf64.exe start
if %ERRORLEVEL% neq 0 ( echo WARN: SamWaf64.exe start failed ^(service not installed or no admin rights?^) & pause )
popd

:: ---- Step 5: Baseline snapshot ----
echo [5/6] Baseline state:
powershell -NoProfile -ExecutionPolicy Bypass -File "%CURDIR%\check_upgrade_state.ps1" -Dir "%TESTDIR%"

:: ---- Step 6: Instructions + HTTP server ----
echo [6/6] Starting HTTP server...
where python >nul 2>nul
if %ERRORLEVEL% neq 0 ( echo FAILED: python not found in PATH & pause & exit /b 1 )

echo.
echo =====================================================================
echo  DO NOT kill any SamWaf64 process from here on, and DO NOT re-run
echo  this script until the whole sequence below is finished.
echo.
echo  1. Open the admin UI and upgrade v1.1.0 -^> v1.1.1. Expect SUCCESS.
echo.
echo  2. In another window, inspect the state:
echo         powershell -File check_upgrade_state.ps1
echo     Expected (this is what proves the root cause):
echo       - .SamWaf64.exe.old exists and is HIDDEN
echo       - the Supervisor process Path now points AT that .old file
echo       - deleting it by hand fails with "Access is denied"
echo.
echo  3. Publish the next version:
echo         publish_test_version.bat v1.1.2
echo.
echo  4. Upgrade v1.1.1 -^> v1.1.2 in the UI. Expect FAILURE:
echo       upgrade error:rename ...\SamWaf64.exe ...\.SamWaf64.exe.old:
echo       Access is denied.
echo =====================================================================
echo.
echo HTTP server started: %UPURL%
echo Root: %WEBDIR%
echo Press Ctrl+C to stop.
echo.
pushd "%WEBDIR%"
python -m http.server 8111
popd
endlocal
exit /b 0

:: ---------------------------------------------------------------------
:build
if not exist "%CURDIR%\release\githubci\%~1" mkdir "%CURDIR%\release\githubci\%~1"
go build -ldflags="-X SamWaf/global.GWAF_RELEASE=true -X SamWaf/global.GWAF_RELEASE_VERSION_NAME=%VERNAME% -X SamWaf/global.GWAF_RELEASE_VERSION=%~1 -X SamWaf/global.GUPDATE_VERSION_URL=%UPURL% -s -w" -o "%CURDIR%\release\githubci\%~1\SamWaf64.exe" ./cmd/samwaf/main.go
if %ERRORLEVEL% neq 0 ( echo FAILED: %~1 build error & pause & exit /b 1 )
echo   OK: release\githubci\%~1\SamWaf64.exe
exit /b 0

:publish
"%GENTOOL%" -desc "local-test-%~1" -o "%WEBDIR%\samwaf_update" -platform windows-amd64 "%CURDIR%\release\githubci\%~1\SamWaf64.exe" %~1
if %ERRORLEVEL% neq 0 ( echo FAILED: publish %~1 error & pause & exit /b 1 )
echo   OK: release\web\samwaf_update\%~1\windows-amd64.gz
exit /b 0
