GOPROXY=https://mirrors.aliyun.com/goproxy/,direct;GO111MODULE=auto
GOPROXY=https://goproxy.cn,direct;GO111MODULE=auto

静态打包
go-bindata-assetfs.exe -o=vue/vue.go -pkg=vue vue/dist/...