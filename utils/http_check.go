package utils

import (
	"SamWaf/common/zlog"
	"fmt"
	"net/http"
	"strings"
)

// 附件检测 - 多种方式综合判断
func checkAttachment(res *http.Response, contentType string) bool {

	contentDisposition := res.Header.Get("Content-Disposition")
	if contentDisposition != "" {
		// 1. 检查 attachment 标识
		if strings.Contains(strings.ToLower(contentDisposition), "attachment") {
			return true
		}
		// 2. 检查 filename 参数（即使没有 attachment，有 filename 也可能是下载）
		if strings.Contains(strings.ToLower(contentDisposition), "filename") {
			return true
		}
	}

	// 3. 检查常见的下载文件 Content-Type
	downloadContentTypes := []string{
		// 通用下载类型
		"application/octet-stream",
		"application/force-download",
		"application/download",
		"application/x-download",

		// Office 文档
		"application/vnd.ms-excel",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", // .xlsx
		"application/vnd.ms-powerpoint",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation", // .pptx
		"application/msword",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document", // .docx

		// 压缩包
		"application/zip",
		"application/x-zip-compressed",
		"application/rar",
		"application/x-rar-compressed",
		"application/x-7z-compressed",
		"application/gzip",
		"application/x-tar",

		// APK
		"application/vnd.android.package-archive", // .apk

		// 虚拟机/磁盘镜像
		"application/x-qemu-disk",           // .qcow2
		"application/x-vmdk",                // .vmdk
		"application/x-vdi",                 // .vdi
		"application/x-vhd",
		"application/x-vhdx",
		"application/x-ovf",
		"application/ovf",
		"application/x-ova",
		"application/ova",
		"application/x-disk-image",          // .img, .raw

		// 其他压缩格式
		"application/x-7z-compressed",
		"application/x-gzip",
		"application/x-bzip2",
		"application/x-lzip",
		"application/x-lzma",
		"application/x-xz",
		"application/zstd",

		// 安装包/可执行文件
		"application/x-msdownload",          // .exe
		"application/x-msi",                 // .msi
		"application/x-apple-diskimage",     // .dmg
		"application/x-executable",          // Linux binary
		"application/x-sharedlib",           // .so
		"application/vnd.debian.binary-package", // .deb
		"application/x-rpm",                 // .rpm

		// 音视频
		"video/*",
		"video/mp4",
		"video/x-matroska",
		"video/x-msvideo",
		"video/quicktime",
		"video/x-flv",
		"audio/*",
		"audio/mpeg",
		"audio/x-wav",
		"audio/flac",
		"audio/aac",

		// 文档
		"application/pdf",
		"application/postscript",
		"application/epub+zip",
		"application/fb2+zip",
	}

	for _, downloadType := range downloadContentTypes {
		if strings.Contains(strings.ToLower(contentType), downloadType) {
			return true
		}
	}

	// 4. 检查 URL 中的下载相关关键词
	if res.Request != nil && res.Request.URL != nil {
		urlPath := strings.ToLower(res.Request.URL.Path)
		urlQuery := strings.ToLower(res.Request.URL.RawQuery)

		// 检查查询参数中的下载标识
		downloadParams := []string{"download=", "export=", "attachment=", "file="}
		for _, param := range downloadParams {
			if strings.Contains(urlQuery, param) {
				return true
			}
		}


		// 5. 检查常见的下载文件扩展名
		downloadExtensions := []string{
			// 压缩包 / 归档
			".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
			".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz",
			".lz", ".lzma", ".zst", ".sz", ".cpio",
			".iso.gz", ".img.gz",

			// 可执行文件 / 安装包
			".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm",
			".app", ".pkg.tar.zst", ".snap", ".flatpak",
			".crx", ".xapk", ".ipsw",
			".ppam", ".xlam", ".dotm",

			// Office 文档
			".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",

			// 虚拟机 / 磁盘镜像
			".qcow2", ".qcow", ".vmdk", ".vdi", ".vhdx", ".vhd",
			".ova", ".ovf", ".hdd", ".wim", ".esd",

			// 光盘 / 镜像
			".iso", ".img", ".bin", ".cue", ".nrg", ".dmg",

			// APK
			".apk",

			// 备份 / 数据库
			".backup", ".bak", ".sql", ".dump", ".db", ".sqlite",
			".mdb", ".fdb", ".snapshot", ".img.backup",

			// 音视频
			".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".mpg", ".mpeg",
			".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a",

			// 文档 / 电子书
			".pdf", ".epub", ".mobi", ".azw3", ".fb2", ".cbr", ".cbz", ".djvu", ".ps", ".tex",

			// 容器 / 云原生
			".oci", ".swu",
		}

		for _, ext := range downloadExtensions {
			if strings.HasSuffix(urlPath, ext) {
				return true
			}
		}
	}
	return false
}

// IsStaticAssist 是否是静态资源
func IsStaticAssist(res *http.Response, contentType string) bool {
	//检测附件
	if checkAttachment(res, contentType) {
		zlog.Debug(fmt.Sprintf("检测到附件 %s", res.Request.URL.String()))
		return true
	}
	// 检查请求的Accept头，判断是否为资源类型请求
	if res.Request != nil {
		// 检查Sec-Fetch-Dest头，这是一个更明确的指示
		secFetchDest := res.Request.Header.Get("Sec-Fetch-Dest")
		if secFetchDest == "image" || secFetchDest == "font" ||
			secFetchDest == "audio" || secFetchDest == "video" ||
			secFetchDest == "style" || secFetchDest == "script" {
			return true
		}

		// 2. 检查Accept头时，应该也包含style和script类型
		acceptHeader := res.Request.Header.Get("Accept")
		if acceptHeader != "" {
			// 检查Accept头是否主要请求图片或其他资源类型
			isResourceRequest := strings.HasPrefix(acceptHeader, "image/") ||
				strings.HasPrefix(acceptHeader, "font/") ||
				strings.HasPrefix(acceptHeader, "audio/") ||
				strings.HasPrefix(acceptHeader, "video/") ||
				strings.HasPrefix(acceptHeader, "text/css") ||
				strings.HasPrefix(acceptHeader, "application/javascript") ||
				strings.HasPrefix(acceptHeader, "application/pdf")
			if isResourceRequest {
				return true
			}
		}

		// 3. 检查URL后缀，这是一个常用的判断方法
		if res.Request.URL != nil {
			path := strings.ToLower(res.Request.URL.Path)
			staticExtensions := []string{".js", ".css", ".jpg", ".jpeg", ".png", ".gif", ".ico",
				".svg", ".webp", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".wav",
				".mp4", ".webm", ".pdf", ".swf"}

			for _, ext := range staticExtensions {
				if strings.HasSuffix(path, ext) {
					return true
				}
			}
		}
	}

	//如果检测资源后发现还存在，那么进行判断处理
	var textFields = []string{"application/json", "text/xml", "application/xml",
		"text/plain", "text/html", "text/csv", "application/html"}

	for _, textField := range textFields {
		if strings.Contains(contentType, textField) {
			return false
		}
	}

	// 4. 默认返回值应该更保守，如果无法确定是否为静态资源，应该返回false
	return false
}
