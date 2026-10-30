package wafsec

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

const streamChunkSize = 64 * 1024

var streamMagic = []byte("SWLOGE01")
var ErrStreamAuthentication = errors.New("stream authentication failed")

// NewStreamKey returns a random data key and its instance-key envelope.
func NewStreamKey() ([]byte, string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, "", err
	}
	wrapped, err := DataEncrypt(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		return nil, "", err
	}
	return key, wrapped, nil
}

func UnwrapStreamKey(wrapped string) ([]byte, error) {
	if !IsDataKeyCiphertext(wrapped) {
		return nil, ErrStreamAuthentication
	}
	text, err := DataDecrypt(wrapped, nil)
	if err != nil {
		return nil, ErrStreamAuthentication
	}
	key, err := base64.StdEncoding.DecodeString(text)
	if err != nil || len(key) != 32 {
		return nil, ErrStreamAuthentication
	}
	return key, nil
}

type StreamWriter struct {
	dst    io.Writer
	aead   cipher.AEAD
	header []byte
	seq    uint64
	buf    []byte
	err    error
	closed bool
}

// NewStreamWriter binds an authenticated stream to contextID; Close is required.
func NewStreamWriter(dst io.Writer, key []byte, contextID string) (*StreamWriter, error) {
	if len(key) != 32 || dst == nil {
		return nil, errors.New("invalid stream options")
	}
	header := make([]byte, 80)
	copy(header, streamMagic)
	if _, err := io.ReadFull(rand.Reader, header[8:44]); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(header[44:48], streamChunkSize)
	digest := sha256.Sum256([]byte(contextID))
	copy(header[48:], digest[:])
	aead, err := streamAEAD(key, header[8:40])
	if err != nil {
		return nil, err
	}
	if err = streamWriteAll(dst, header); err != nil {
		return nil, err
	}
	return &StreamWriter{dst: dst, aead: aead, header: header, buf: make([]byte, 0, streamChunkSize)}, nil
}

func streamAEAD(key, salt []byte) (cipher.AEAD, error) {
	derived := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, key, salt, []byte("samwaf/log-export/stream/v1")), derived); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derived)
	clear(derived)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func streamNonce(header []byte, seq uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce, header[40:44])
	binary.BigEndian.PutUint64(nonce[4:], seq)
	return nonce
}

func streamAAD(header []byte, seq uint64, n uint32) []byte {
	aad := make([]byte, len(header)+12)
	copy(aad, header)
	binary.BigEndian.PutUint64(aad[len(header):], seq)
	binary.BigEndian.PutUint32(aad[len(header)+8:], n)
	return aad
}

func streamWriteAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (w *StreamWriter) record(p []byte) error {
	if w.seq == ^uint64(0) {
		return errors.New("stream sequence exhausted")
	}
	n := uint32(len(p))
	sealed := w.aead.Seal(nil, streamNonce(w.header, w.seq), p, streamAAD(w.header, w.seq, n))
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], n)
	if err := streamWriteAll(w.dst, length[:]); err != nil {
		return err
	}
	if err := streamWriteAll(w.dst, sealed); err != nil {
		return err
	}
	w.seq++
	return nil
}

func (w *StreamWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("stream closed")
	}
	if w.err != nil {
		return 0, w.err
	}
	written := 0
	for len(p) > 0 {
		n := min(streamChunkSize-len(w.buf), len(p))
		w.buf = append(w.buf, p[:n]...)
		p = p[n:]
		written += n
		if len(w.buf) == streamChunkSize {
			w.err = w.record(w.buf)
			if w.err != nil {
				return written, w.err
			}
			w.buf = w.buf[:0]
		}
	}
	return written, nil
}

func (w *StreamWriter) Close() error {
	if w.closed {
		return w.err
	}
	w.closed = true
	if w.err == nil && len(w.buf) > 0 {
		w.err = w.record(w.buf)
	}
	clear(w.buf)
	w.buf = nil
	if w.err == nil {
		w.err = w.record(nil)
	}
	return w.err
}

type StreamReader struct {
	src    io.Reader
	aead   cipher.AEAD
	header []byte
	seq    uint64
	buf    []byte
	done   bool
	err    error
}

func NewStreamReader(src io.Reader, key []byte, contextID string) (*StreamReader, error) {
	if src == nil || len(key) != 32 {
		return nil, ErrStreamAuthentication
	}
	header := make([]byte, 80)
	if _, err := io.ReadFull(src, header); err != nil {
		return nil, ErrStreamAuthentication
	}
	digest := sha256.Sum256([]byte(contextID))
	if !bytes.Equal(header[:8], streamMagic) || binary.BigEndian.Uint32(header[44:48]) != streamChunkSize || !bytes.Equal(header[48:], digest[:]) {
		return nil, ErrStreamAuthentication
	}
	aead, err := streamAEAD(key, header[8:40])
	if err != nil {
		return nil, err
	}
	return &StreamReader{src: src, aead: aead, header: header}, nil
}

func (r *StreamReader) next() error {
	var length [4]byte
	if _, err := io.ReadFull(r.src, length[:]); err != nil {
		return ErrStreamAuthentication
	}
	n := binary.BigEndian.Uint32(length[:])
	if n > streamChunkSize || r.seq == ^uint64(0) {
		return ErrStreamAuthentication
	}
	sealed := make([]byte, int(n)+r.aead.Overhead())
	if _, err := io.ReadFull(r.src, sealed); err != nil {
		return ErrStreamAuthentication
	}
	plain, err := r.aead.Open(nil, streamNonce(r.header, r.seq), sealed, streamAAD(r.header, r.seq, n))
	if err != nil {
		return ErrStreamAuthentication
	}
	r.seq++
	if n == 0 {
		var extra [1]byte
		count, err := io.ReadFull(r.src, extra[:])
		if count != 0 || err != io.EOF {
			return ErrStreamAuthentication
		}
		r.done = true
		return io.EOF
	}
	r.buf = plain
	return nil
}

func (r *StreamReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	if r.done {
		return 0, io.EOF
	}
	if len(r.buf) == 0 {
		if err := r.next(); err != nil {
			r.err = err
			return 0, err
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}
