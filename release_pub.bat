@echo on
chcp 65001
set currentpath=%cd%
set currentversion=v1.1.2
set currentdescription=更新了好多内容
%currentpath%\setup\go_gen_updatefile\go_gen_updatefile.exe -desc %currentdescription% -o %currentpath%\release\web\samwaf_update -platform windows-amd64 %currentpath%\release\SamWaf64.exe %currentversion% 
%currentpath%\setup\go_gen_updatefile\go_gen_updatefile.exe -desc %currentdescription% -o %currentpath%\release\web\samwaf_update -platform linux-amd64 %currentpath%\release\SamWafLinux64 %currentversion% 