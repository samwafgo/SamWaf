@echo on
chcp 65001
set currentpath=%cd%
set currentversion=v1.3.7-beta.2
set currentdescription=本地测试
%currentpath%\setup\go_gen_updatefile\go_gen_updatefile.exe -desc %currentdescription% -o %currentpath%\release\web\win7\samwaf_update -platform windows-amd64 %currentpath%\release\githubci\%currentversion%\SamWaf64ForWin7Win8Win2008.exe %currentversion%
