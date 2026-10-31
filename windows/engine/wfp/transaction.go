// Evgenium addition to github.com/tailscale/wf (upstream 6fbb0a674ee6).
// Distributed under the same BSD license as upstream (see LICENSE).
package wf

import "golang.org/x/sys/windows"

// Transaction applies a policy atomically. An interrupted transaction retains
// the previous policy, including on process termination before Commit.
func (s *Session) Transaction(fn func() error) error {
	dll := windows.NewLazySystemDLL("fwpuclnt.dll")
	call := func(name string) error {
		r, _, _ := dll.NewProc(name).Call(uintptr(s.handle), 0)
		if r != 0 {
			return windows.Errno(r)
		}
		return nil
	}
	if e := call("FwpmTransactionBegin0"); e != nil {
		return e
	}
	committed := false
	defer func() {
		if !committed {
			_ = call("FwpmTransactionAbort0")
		}
	}()
	if e := fn(); e != nil {
		return e
	}
	if e := call("FwpmTransactionCommit0"); e != nil {
		return e
	}
	committed = true
	return nil
}
