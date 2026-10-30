//go:build !windows

package filelease

import (
	"context"
	"fmt"
	"syscall"
)

func acquire(ctx context.Context, path string, exclusive bool) (*Lease, error) {
	f, err := openLockFile(path)
	if err != nil {
		return nil, err
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	how |= syscall.LOCK_NB
	fd := int(f.Fd())
	for {
		err = syscall.Flock(fd, how)
		if err == nil {
			return &Lease{f: f, path: path}, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			_ = f.Close()
			return nil, fmt.Errorf("acquire file lease %s: %w", path, err)
		}
		if werr := wait(ctx); werr != nil {
			_ = f.Close()
			return nil, werr
		}
	}
}
