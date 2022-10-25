SET CGO_ENABLED=0
SET GOOS=windows
SET GOARCH=amd64
go build -o %cd%/release/SamWaf64.exe main.go localdb.go localserver.go wafengine.go

SET CGO_ENABLED=0
SET GOOS=windows
SET GOARCH=386
go build -o %cd%/release/SamWaf32.exe main.go localdb.go localserver.go wafengine.go

SET CGO_ENABLED=0
SET GOOS=linux
SET GOARCH=amd64
go build -o %cd%/release/SamWafLinux64 main.go localdb.go localserver.go wafengine.go

