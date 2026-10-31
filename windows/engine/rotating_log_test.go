package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLogBoundedWhileCoreRuns(t *testing.T) {
	p := filepath.Join(t.TempDir(), "engine.log")
	w, e := openLog(p, 1024)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 100; i++ {
		if n, e := w.Write(bytes.Repeat([]byte{byte(i)}, 90)); n != 90 || e != nil {
			t.Fatal(n, e)
		}
	}
	w.Close()
	for _, name := range []string{p, p + ".1"} {
		st, e := os.Stat(name)
		if e != nil || st.Size() > 1024 {
			t.Fatal(st, e)
		}
	}
	if _, e := w.Write([]byte("closed")); e == nil {
		t.Fatal("write after close accepted")
	}
}
