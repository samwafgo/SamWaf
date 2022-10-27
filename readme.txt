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