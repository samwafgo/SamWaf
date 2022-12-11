SET CGO_ENABLED=1
SET GOOS=linux
SET GOARCH=amd64
go build -ldflags="-s -w -extldflags "-static"" -o %cd%/release/SamWafLinux64 main.go localdb.go localserver.go wafengine.go localtaskcounter.go && %cd%/upx/win64/upx -9  %cd%/release/SamWafLinux64