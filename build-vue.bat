@echo off

REM 获取当前目录
set current_dir=%CD%

REM 编译 Vue.js 源码
cd /d %current_dir%\localwaf 
call npm run build
 
 
REM 切换回原来的目录并执行 go-bindata-assetfs.exe 命令
cd /d %current_dir%

call build-vue_to_go.bat