package middleware

import "testing"

func TestLogExportDownloadPathScope(t *testing.T) {
	for _, path := range []string{
		"/api/v1/waflog/exports/1234567890abcdef/download",
		"/api/v1/waflog/exports/task-1234567890abcdef/download",
	} {
		if !isLogExportDownloadPath(path) {
			t.Errorf("download path rejected: %s", path)
		}
	}
	for _, path := range []string{
		"/api/v1/waflog/exports", "/api/v1/waflog/exports/id/download-ticket",
		"/api/v1/waflog/exports/id/cancel", "/api/v1/waflog/exports//download",
		"/api/v1/waflog/exports/id/download/extra", "/api/v1/waflog/exports/id/download/",
		"/api/v2/waflog/exports/id/download", "/api/v1/waflog/other/id/download",
		"/api/v1/waflog/exports/id/Download", "//api/v1/waflog/exports/id/download",
		"/prefix/api/v1/waflog/exports/id/download",
	} {
		if isLogExportDownloadPath(path) {
			t.Errorf("non-download path accepted: %s", path)
		}
	}
}
