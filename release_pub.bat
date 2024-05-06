@echo on
chcp 65001
set currentpath=%cd%
set currentversion=v1.1.6
set currentdescription=信息脱敏处理，建议升级
%currentpath%\setup\go_gen_updatefile\go_gen_updatefile.exe -desc %currentdescription% -o %currentpath%\release\web\samwaf_update -platform windows-amd64 %currentpath%\release\SamWaf64.exe %currentversion% 
%currentpath%\setup\go_gen_updatefile\go_gen_updatefile.exe -desc %currentdescription% -o %currentpath%\release\web\samwaf_update -platform linux-amd64 %currentpath%\release\SamWafLinux64 %currentversion%