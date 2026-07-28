@echo off
setlocal

:: Publish one already-built test version to the local update server, so
:: the running instance sees it as the next upgrade target.
:: Companion to build_test_upgrade_twice.bat -- it deliberately publishes
:: only ONE version at a time, because samwaf_update\windows-amd64.json
:: holds a single target version.
::
::   publish_test_version.bat v1.1.2
::
:: Never kills or touches any running process.

set "CURDIR=%~dp0"
set "CURDIR=%CURDIR:~0,-1%"
set "WEBDIR=%CURDIR%\release\web"
set "GENTOOL=%CURDIR%\setup\go_gen_updatefile\go_gen_updatefile.exe"

set "VER=%~1"
if "%VER%"=="" set "VER=v1.1.2"

if not exist "%CURDIR%\release\githubci\%VER%\SamWaf64.exe" (
  echo FAILED: release\githubci\%VER%\SamWaf64.exe not found.
  echo Run build_test_upgrade_twice.bat first, or build that version.
  pause
  exit /b 1
)

"%GENTOOL%" -desc "local-test-%VER%" -o "%WEBDIR%\samwaf_update" -platform windows-amd64 "%CURDIR%\release\githubci\%VER%\SamWaf64.exe" %VER%
if %ERRORLEVEL% neq 0 ( echo FAILED: publish %VER% error & pause & exit /b 1 )

echo OK: published %VER%
type "%WEBDIR%\samwaf_update\windows-amd64.json"
echo.
echo Now trigger the upgrade from the admin UI.
endlocal
