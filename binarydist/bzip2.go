package binarydist

import (
	"github.com/dsnet/compress/bzip2"
	"io"
)

type bzip2Writer struct {
	w io.Writer
	r *bzip2.Writer
}

func (w *bzip2Writer) Write(b []byte) (int, error) {
	return w.r.Write(b)
}
func (w *bzip2Writer) Close() error {
	err := w.r.Close()
	if err != nil {
		return err
	}
	// Since the underlying writer is the one we passed in, we don't need to
	// close it again; it's the responsibility of the caller to close it.
	return nil
}
func newBzip2Writer(w io.Writer) (io.WriteCloser, error) {
	r, err := bzip2.NewWriter(w, nil)
	return &bzip2Writer{w: w, r: r}, err
}
