package httpbody

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
)

type closeTrackingBody struct {
	io.Reader
	closed bool
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}

func TestReadPrefixReplaysReadErrorAndCloses(t *testing.T) {
	body := &closeTrackingBody{Reader: iotest.TimeoutReader(iotest.OneByteReader(strings.NewReader("abc")))}
	r := &http.Request{Body: body, ContentLength: 3}
	prefix, err := ReadPrefix(r, 3)
	if string(prefix) != "a" || !errors.Is(err, iotest.ErrTimeout) {
		t.Fatalf("prefix=%q err=%v", prefix, err)
	}
	replay, err := io.ReadAll(r.Body)
	if string(replay) != "a" || !errors.Is(err, iotest.ErrTimeout) {
		t.Fatalf("replay=%q err=%v", replay, err)
	}
	if err := r.Body.Close(); err != nil || !body.closed {
		t.Fatalf("original body closed=%v err=%v", body.closed, err)
	}
}
