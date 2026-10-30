package api

import (
	"SamWaf/service/waf_service"
	"errors"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type closeTrackReader struct {
	data     string
	pos      int
	closeErr error
	closed   bool
}

func (r *closeTrackReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *closeTrackReader) Close() error {
	r.closed = true
	return r.closeErr
}

func TestStreamLogExportDownloadCompletesOnExactLength(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest("GET", "/api/v1/waflog/exports/task-1/download?ticket=x", nil)
	reader := &closeTrackReader{data: "zip-bytes"}
	var completeErr error
	download := &waf_service.LogExportDownload{Size: int64(len(reader.data)), Reader: reader, Complete: func(err error) { completeErr = err }}

	streamLogExportDownload(ctx, "task-1", download)

	if recorder.Code != 200 || recorder.Body.String() != reader.data {
		t.Fatalf("下载响应异常: code=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if completeErr != nil {
		t.Fatalf("完整下载不应上报错误: %v", completeErr)
	}
	if !reader.closed {
		t.Fatal("下载结束后 Reader 未关闭")
	}
}

func TestStreamLogExportDownloadReportsShortTransfer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest("GET", "/api/v1/waflog/exports/task-1/download?ticket=x", nil)
	reader := &closeTrackReader{data: "short"}
	var completeErr error
	download := &waf_service.LogExportDownload{Size: 100, Reader: reader, Complete: func(err error) { completeErr = err }}

	streamLogExportDownload(ctx, "task-1", download)

	if !errors.Is(completeErr, io.ErrUnexpectedEOF) {
		t.Fatalf("短传输应上报 io.ErrUnexpectedEOF，实际 %v", completeErr)
	}
	if !reader.closed {
		t.Fatal("下载结束后 Reader 未关闭")
	}
}
