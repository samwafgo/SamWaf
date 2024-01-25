@echo on
chcp 65001
set testpath=C:\huawei\goproject\SamWafUpdate\
set currentpath=%cd%
set currentversion=v1.1.2024
set currentdescription=测试升级
%currentpath%\setup\go_gen_updatefile\go_gen_updatefile.exe -desc %currentdescription% -o %currentpath%\release\web\test_update -platform windows-amd64 %testpath%\SamWafUpdate.exe %currentversion%