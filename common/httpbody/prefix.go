package httpbody

import (
	"bytes"
	"io"
	"net/http"
)

// ReadPrefix reads up to limit bytes and restores them ahead of the unread request body.
func ReadPrefix(r *http.Request, limit int64) ([]byte, error) {
	body := r.Body
	if body == nil || body == http.NoBody {
		return nil, nil
	}

	prefix, err := io.ReadAll(io.LimitReader(body, limit))
	Replay(r, bytes.NewReader(prefix), err)
	return prefix, err
}

// Replay restores a consumed prefix and preserves an observed error at the end of it.
func Replay(r *http.Request, prefix io.Reader, readErr error) {
	body := r.Body
	var tail io.Reader = body
	if readErr != nil {
		tail = readError{readErr}
	}
	if prefix != nil {
		tail = io.MultiReader(prefix, tail)
	}
	r.Body = &replayBody{Reader: tail, Closer: body}
}

type replayBody struct {
	io.Reader
	io.Closer
}

// Replay an observed read error after the bytes returned with it.
type readError struct{ err error }

func (r readError) Read([]byte) (int, error) { return 0, r.err }
