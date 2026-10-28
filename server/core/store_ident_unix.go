//go:build unix

package core

import (
	"os"
	"syscall"
)

func fileOwner(st os.FileInfo) (int, int) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1
	}
	return int(sys.Uid), int(sys.Gid)
}

func chownFile(path string, uid, gid int) {
	if uid >= 0 && gid >= 0 {
		_ = os.Chown(path, uid, gid)
	}
}
