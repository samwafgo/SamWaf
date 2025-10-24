SET CGO_ENABLED=1
SET GOOS=darwin
SET GOARCH=amd64
SET GIN_MODE=release
go build -ldflags="-X SamWaf/global.GWAF_RELEASE=true -X SamWaf/global.GWAF_RELEASE_VERSION_NAME=20250928 -X SamWaf/global.GWAF_RELEASE_VERSION=v1.3.16 -s -w" -o %cd%/release/SamWafDarwinAmd64.exe main.go