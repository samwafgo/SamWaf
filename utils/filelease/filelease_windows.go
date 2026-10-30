//go:build windows

package filelease

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows"
)

func acquire(ctx context.Context, path string, exclusive bool) (*Lease, error) {
	f, err := openLockFile(path)
	if err != nil {
		return nil, err
	}
	h := windows.Handle(f.Fd())
	flags := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY)
	if exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	var overlapped windows.Overlapped
	for {
		err = windows.LockFileEx(h, flags, 0, 1, 0, &overlapped)
		if err == nil {
			return &Lease{f: f, path: path}, nil
		}
		if err != windows.ERROR_LOCK_VIOLATION && err != windows.ERROR_SHARING_VIOLATION {
			_ = f.Close()
			return nil, fmt.Errorf("acquire file lease %s: %w", path, err)
		}
		if werr := wait(ctx); werr != nil {
			_ = f.Close()
			return nil, werr
		}
	}
}
