package public

import (
	"embed"
	"io/fs"
	"strings"
)

//go:embed all:dist
var dist embed.FS

//go:embed web_frontend.txt
var webFrontendStamp string

var Public, _ = fs.Sub(dist, "dist")

// WebFrontendVersion 返回内嵌管理端前端的版本。
// 戳文件由 CI 的 .github/scripts/fetch_web_dist.sh 写入；
// 本地手工放置的 dist 保持入库默认值"本地构建"。
func WebFrontendVersion() string {
	for _, line := range strings.Split(webFrontendStamp, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "version="); ok {
			if v = strings.TrimSpace(v); v != "" {
				return v
			}
		}
	}
	return "未知"
}
