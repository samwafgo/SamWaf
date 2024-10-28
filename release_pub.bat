@echo on
chcp 65001
set currentpath=%cd%
set currentversion=v1.3.6
set currentdescription=请在闲时升级,新增ssl证书夹,自定义ip库等
%currentpath%\setup\go_gen_updatefile\go_gen_updatefile.exe -desc %currentdescription% -o %currentpath%\release\web\samwaf_update -platform windows-amd64 %currentpath%\release\githubci\%currentversion%\SamWaf64.exe %currentversion%
%currentpath%\setup\go_gen_updatefile\go_gen_updatefile.exe -desc %currentdescription% -o %currentpath%\release\web\samwaf_update -platform linux-amd64 %currentpath%\release\githubci\%currentversion%\SamWafLinux64 %currentversion%
%currentpath%\setup\go_gen_updatefile\go_gen_updatefile.exe -desc %currentdescription% -o %currentpath%\release\web\win7\samwaf_update -platform windows-amd64 %currentpath%\release\githubci\%currentversion%\SamWaf64ForWin7Win8Win2008.exe %currentversion%
