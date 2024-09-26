@echo on
chcp 65001
set currentpath=%cd%
set currentversion=v1.3.3
set currentdescription=请在闲时升级,新增访客Proxy自定义header等
%currentpath%\setup\go_gen_updatefile\go_gen_updatefile.exe -desc %currentdescription% -o %currentpath%\release\web\samwaf_update -platform windows-amd64 %currentpath%\release\githubci\%currentversion%\SamWaf64.exe %currentversion%
%currentpath%\setup\go_gen_updatefile\go_gen_updatefile.exe -desc %currentdescription% -o %currentpath%\release\web\samwaf_update -platform linux-amd64 %currentpath%\release\githubci\%currentversion%\SamWafLinux64 %currentversion%