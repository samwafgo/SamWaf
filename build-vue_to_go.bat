go-bindata-assetfs.exe -o=vue/vue.go -pkg=vue vue/dist/...

set current_dir=%CD%
del %current_dir%\bindata.go 2>nul