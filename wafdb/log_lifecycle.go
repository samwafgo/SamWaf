package wafdb

import (
	"context"
	"path/filepath"
	"sync"

	"SamWaf/utils"
	"SamWaf/utils/filelease"
)

// logLifecycleLease coordinates source enumeration, snapshots and storage changes.
var logLifecycleLease = newLogLifecycleLease()

// logLifecycleLockPath is the cross-process lease file. Production uses the fixed data path;
// tests and special executors may inject another absolute regular-file path.
var logLifecycleLockPath = defaultLogLifecycleLockPath()

func defaultLogLifecycleLockPath() string {
	return filepath.Join(utils.GetCurrentDir(), "data", ".samwaf_log_lifecycle.lock")
}

// SetLogLifecycleLockPath overrides the cross-process lease path. Passing "" disables the
// file lease and keeps only the in-process lease. Intended for isolated tests or a service
// executor with its own lease file.
func SetLogLifecycleLockPath(path string) {
	logLifecycleLockPath = filepath.Clean(path)
}

type logLease struct {
	mu                      sync.Mutex
	changed                 chan struct{}
	readers, waitingWriters int
	writer                  bool
}

func newLogLifecycleLease() *logLease { return &logLease{changed: make(chan struct{})} }
func (l *logLease) notify()           { close(l.changed); l.changed = make(chan struct{}) }
func (l *logLease) acquire(ctx context.Context, write bool) (func(), error) {
	l.mu.Lock()
	if write {
		l.waitingWriters++
	}
	for {
		if err := ctx.Err(); err != nil {
			if write {
				l.waitingWriters--
				l.notify()
			}
			l.mu.Unlock()
			return nil, err
		}
		if !l.writer && ((write && l.readers == 0) || (!write && l.waitingWriters == 0)) {
			if write {
				l.waitingWriters--
				l.writer = true
			} else {
				l.readers++
			}
			l.mu.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					l.mu.Lock()
					if write {
						l.writer = false
					} else {
						l.readers--
					}
					l.notify()
					l.mu.Unlock()
				})
			}, nil
		}
		changed := l.changed
		l.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-changed:
		}
		l.mu.Lock()
	}
}

// AcquireLogRead must cover enumeration and all reads; callers must not nest leases.
func AcquireLogRead(ctx context.Context) (func(), error) {
	return acquireLogLifecycle(ctx, false)
}

// AcquireLogWrite covers the complete rotation, deletion or connection replacement.
func AcquireLogWrite(ctx context.Context) (func(), error) {
	return acquireLogLifecycle(ctx, true)
}

// AcquireExclusive exposes the platform file lease for an executor-owned fixed lock file.
func AcquireExclusive(ctx context.Context, path string) (*filelease.Lease, error) {
	return filelease.AcquireExclusive(ctx, path)
}

func acquireLogLifecycle(ctx context.Context, write bool) (func(), error) {
	local, err := logLifecycleLease.acquire(ctx, write)
	if err != nil {
		return nil, err
	}
	if logLifecycleLockPath == "" || logLifecycleLockPath == "." {
		return local, nil
	}
	var fl *filelease.Lease
	if write {
		fl, err = filelease.AcquireExclusive(ctx, logLifecycleLockPath)
	} else {
		fl, err = filelease.AcquireShared(ctx, logLifecycleLockPath)
	}
	if err != nil {
		local()
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			fl.Release()
			local()
		})
	}, nil
}
