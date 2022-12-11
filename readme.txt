GOPROXY=https://mirrors.aliyun.com/goproxy/,direct;GO111MODULE=auto
GOPROXY=https://goproxy.cn,direct;GO111MODULE=auto

静态打包
go-bindata-assetfs.exe -o=vue/vue.go -pkg=vue vue/dist/...


go语言实现string转换int

string转成int：

int, err := strconv.Atoi(string)
string转成int64：

int64, err := strconv.ParseInt(string, 10, 64)
附：

int转成string：

string := strconv.Itoa(int)
int64转成string：

string := strconv.FormatInt(int64,10)



# 远程linux调试
go env -w GOPROXY=goproxy.cn,direct
go install github.com/go-delve/delve/cmd/dlv@latest

/root/go/bin/dlv --listen=:26667 --headless=true --api-version=2 --accept-multiclient exec ./SamWafLinux64.exe