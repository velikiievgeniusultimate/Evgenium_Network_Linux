package main

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
)

func installedBlueStacksApplications() []string {
	result := []string{}
	for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")} {
		if root == "" {
			continue
		}
		for _, directory := range []string{"BlueStacks_nxt", "BlueStacks"} {
			for _, exe := range blueStacksProcesses {
				p := filepath.Join(root, directory, exe)
				if info, err := os.Stat(p); err == nil && !info.IsDir() {
					result = append(result, p)
				}
			}
		}
	}
	return result
}

// Xray compares full paths case-sensitively. Resolve the filesystem's canonical
// name so C:\Windows\system32\curl.exe matches its real System32 process path.
func canonicalApplication(path string) string {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return filepath.ToSlash(path)
	}
	h, e := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if e != nil {
		return filepath.ToSlash(path)
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 32768)
	n, e := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
	if e != nil || n == 0 || int(n) >= len(buf) {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(strings.TrimPrefix(windows.UTF16ToString(buf[:n]), `\\?\`))
}
func routingApplications(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	for _, p := range values {
		if filepath.IsAbs(p) {
			add(canonicalApplication(p))
		} else {
			add(p)
			for _, v := range appPaths([]string{p}) {
				add(canonicalApplication(v))
			}
		}
	}
	return result
}
