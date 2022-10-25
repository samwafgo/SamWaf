SET CGO_ENABLED=1
SET GOOS=windows
SET GOARCH=amd64
SET GIN_MODE=release
go build -o %cd%/release/SamWaf64.exe main.go localdb.go localserver.go wafengine.go
