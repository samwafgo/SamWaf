SET CGO_ENABLED=1
SET GOOS=darwin
SET GOARCH=arm64
SET GIN_MODE=release
go build -ldflags="-X SamWaf/global.GWAF_RELEASE=true -X SamWaf/global.GWAF_RELEASE_VERSION_NAME=20260708 -X SamWaf/global.GWAF_RELEASE_VERSION=v1.3.21 -s -w" -o %cd%/release/SamWafDarwinArm64.exe ./cmd/samwaf/main.go