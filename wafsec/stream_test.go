package wafsec

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func sealStream(t *testing.T, key, plain []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := NewStreamWriter(&out, key, "task-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func TestStreamRoundTripAndRandomization(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	for _, size := range []int{0, 1, 65536, 65537, 200000} {
		plain := bytes.Repeat([]byte("x"), size)
		sealed := sealStream(t, key, plain)
		if bytes.Equal(sealed, sealStream(t, key, plain)) {
			t.Fatal("streams repeated")
		}
		r, err := NewStreamReader(bytes.NewReader(sealed), key, "task-1")
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("size %d: %v", size, err)
		}
	}
}
func TestStreamAuthenticationFailures(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	sealed := sealStream(t, key, bytes.Repeat([]byte("x"), 65536*2))
	cases := map[string][]byte{"no-final": sealed[:len(sealed)-20], "short-final": sealed[:len(sealed)-1], "trailing": append(append([]byte(nil), sealed...), 1), "short-header": sealed[:79]}
	altered := append([]byte(nil), sealed...)
	altered[100] ^= 1
	cases["modified"] = altered
	swapped := append([]byte(nil), sealed...)
	record := 65536 + 20
	copy(swapped[80:80+record], sealed[80+record:80+2*record])
	copy(swapped[80+record:80+2*record], sealed[80:80+record])
	cases["reordered"] = swapped
	changedHeader := append([]byte(nil), sealed...)
	changedHeader[10] ^= 1
	cases["header"] = changedHeader
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := NewStreamReader(bytes.NewReader(data), key, "task-1")
			if err == nil {
				_, err = io.ReadAll(r)
			}
			if !errors.Is(err, ErrStreamAuthentication) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	for _, tc := range []struct {
		key []byte
		id  string
	}{{bytes.Repeat([]byte{4}, 32), "task-1"}, {key, "task-2"}} {
		r, err := NewStreamReader(bytes.NewReader(sealed), tc.key, tc.id)
		if err == nil {
			_, err = io.ReadAll(r)
		}
		if !errors.Is(err, ErrStreamAuthentication) {
			t.Fatalf("accepted wrong identity/key: %v", err)
		}
	}
}
func TestStreamRecordLayoutAndManualOpen(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	plain := bytes.Repeat([]byte("a"), streamChunkSize+10)
	sealed := sealStream(t, key, plain)
	if len(sealed) < 80 {
		t.Fatal("short stream")
	}
	header := sealed[:80]
	if !bytes.Equal(header[:8], streamMagic) {
		t.Fatal("magic")
	}
	if binary.BigEndian.Uint32(header[44:48]) != streamChunkSize {
		t.Fatal("chunk size")
	}
	digest := sha256.Sum256([]byte("task-1"))
	if !bytes.Equal(header[48:], digest[:]) {
		t.Fatal("context digest")
	}
	aead, err := streamAEAD(key, header[8:40])
	if err != nil {
		t.Fatal(err)
	}
	off := 80
	seq := uint64(0)
	var recovered []byte
	for {
		if off+4 > len(sealed) {
			t.Fatal("truncated record framing")
		}
		n := binary.BigEndian.Uint32(sealed[off : off+4])
		off += 4
		if n > streamChunkSize || off+int(n)+aead.Overhead() > len(sealed) {
			t.Fatal("record length out of bounds")
		}
		record := sealed[off : off+int(n)+aead.Overhead()]
		off += len(record)
		opened, err := aead.Open(nil, streamNonce(header, seq), record, streamAAD(header, seq, n))
		if err != nil {
			t.Fatalf("record %d rejected by manual open: %v", seq, err)
		}
		recovered = append(recovered, opened...)
		seq++
		if n == 0 {
			break
		}
	}
	if off != len(sealed) || !bytes.Equal(recovered, plain) {
		t.Fatal("layout round trip")
	}
	if bytes.Equal(streamNonce(header, 0), streamNonce(header, 1)) {
		t.Fatal("nonce reuse")
	}
}

func TestStreamRejectsCorruptLengthField(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	sealed := sealStream(t, key, bytes.Repeat([]byte("x"), streamChunkSize))
	for _, pos := range []int{80, 81, 82, 83} {
		data := append([]byte(nil), sealed...)
		data[pos] ^= 0xff
		r, err := NewStreamReader(bytes.NewReader(data), key, "task-1")
		if err == nil {
			_, err = io.ReadAll(r)
		}
		if !errors.Is(err, ErrStreamAuthentication) {
			t.Fatalf("pos %d accepted: %v", pos, err)
		}
	}
}

func TestStreamErrorIsSticky(t *testing.T) {
	boom := errors.New("boom")
	dst := &failAfterWriter{left: 80, err: boom}
	w, err := NewStreamWriter(dst, bytes.Repeat([]byte{5}, 32), "task-1")
	if err != nil {
		t.Fatal(err)
	}
	dst.left = 0
	if _, err = w.Write(make([]byte, streamChunkSize)); !errors.Is(err, boom) {
		t.Fatalf("first error: %v", err)
	}
	dst.left = -1
	if _, err = w.Write([]byte("y")); !errors.Is(err, boom) {
		t.Fatalf("sticky error: %v", err)
	}
	if err = w.Close(); !errors.Is(err, boom) {
		t.Fatalf("close error: %v", err)
	}
	if _, err = w.Write([]byte("z")); err == nil {
		t.Fatal("write after close accepted")
	}
}

type failAfterWriter struct {
	left int
	err  error
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.left < 0 {
		return 0, errors.New("must not be called")
	}
	if w.left == 0 {
		if w.err == nil {
			w.err = errors.New("boom")
		}
		return 0, w.err
	}
	if len(p) > w.left {
		n := w.left
		w.left = 0
		return n, nil
	}
	w.left -= len(p)
	return len(p), nil
}

func TestStreamRejectsMalformedInput(t *testing.T) {
	setupDataKey(t)
	key := bytes.Repeat([]byte{3}, 32)
	if _, err := NewStreamReader(bytes.NewReader(nil), key, "task-1"); !errors.Is(err, ErrStreamAuthentication) {
		t.Fatalf("empty input: %v", err)
	}
	wrapped, err := DataEncrypt(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = UnwrapStreamKey(wrapped); !errors.Is(err, ErrStreamAuthentication) {
		t.Fatalf("short key accepted: %v", err)
	}
}

func TestStreamWrappedKey(t *testing.T) {
	setupDataKey(t)
	key, wrapped, err := NewStreamKey()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapStreamKey(wrapped)
	if err != nil || !bytes.Equal(key, got) {
		t.Fatal(err)
	}
	if _, err = UnwrapStreamKey("plain"); err == nil {
		t.Fatal("accepted unwrapped key")
	}
}
