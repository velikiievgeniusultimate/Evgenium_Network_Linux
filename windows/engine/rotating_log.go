package main

import (
	"io"
	"os"
	"sync"
)

// Bound even a long-running core's errors. No packet payloads are logged.
type rotatingLog struct {
	mu    sync.Mutex
	path  string
	file  *os.File
	size  int64
	limit int64
}

func openLog(path string, limit int64) (*rotatingLog, error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		return nil, e
	}
	st, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	return &rotatingLog{path: path, file: f, size: st.Size(), limit: limit}, nil
}
func (l *rotatingLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return 0, os.ErrClosed
	}
	original := len(p)
	if int64(len(p)) > l.limit {
		p = p[len(p)-int(l.limit):]
	}
	if l.size+int64(len(p)) > l.limit {
		if e := l.file.Close(); e != nil {
			return 0, e
		}
		l.file = nil
		if e := os.Remove(l.path + ".1"); e != nil && !os.IsNotExist(e) {
			return 0, e
		}
		if e := os.Rename(l.path, l.path+".1"); e != nil {
			return 0, e
		}
		f, e := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if e != nil {
			return 0, e
		}
		l.file = f
		l.size = 0
	}
	n, e := l.file.Write(p)
	l.size += int64(n)
	if e != nil {
		return 0, e
	}
	if n != len(p) {
		return 0, io.ErrShortWrite
	}
	return original, nil
}
func (l *rotatingLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	e := l.file.Close()
	l.file = nil
	return e
}
