SET CGO_ENABLED=1
SET GOOS=windows
SET GOARCH=amd64
SET GIN_MODE=release
go build -ldflags="-s -w" -o %cd%/release/SamWaf64.exe main.go localdb.go localserver.go wafengine.go localtaskcounter.go && %cd%/upx/win64/upx -9  %cd%/release/SamWaf64.exe
