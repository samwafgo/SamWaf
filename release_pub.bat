@echo on
chcp 65001
set currentpath=%cd%
set currentversion=v1.3.15
set currentdescription=请在闲时升级,修复bug,新增多项功能，升级前先查看详情，https://doc.samwaf.com/quickstart/Update.html
%currentpath%\setup\go_gen_updatefile\go_gen_updatefile.exe -desc %currentdescription% -o %currentpath%\release\web\samwaf_update -platform windows-amd64 %currentpath%\release\githubci\%currentversion%\SamWaf64.exe %currentversion%
%currentpath%\setup\go_gen_updatefile\go_gen_updatefile.exe -desc %currentdescription% -o %currentpath%\release\web\samwaf_update -platform linux-amd64 %currentpath%\release\githubci\%currentversion%\SamWafLinux64 %currentversion%
%currentpath%\setup\go_gen_updatefile\go_gen_updatefile.exe -desc %currentdescription% -o %currentpath%\release\web\win7\samwaf_update -platform windows-amd64 %currentpath%\release\githubci\%currentversion%\SamWaf64ForWin7Win8Win2008.exe %currentversion%
%currentpath%\setup\go_gen_updatefile\go_gen_updatefile.exe -desc %currentdescription% -o %currentpath%\release\web\samwaf_update -platform linux-arm64 %currentpath%\release\githubci\%currentversion%\SamWafLinuxArm64 %currentversion%