package core

import "os"

func fileIdent(path string) (mode os.FileMode, uid, gid int) {
	mode = 0o600
	uid, gid = -1, -1
	st, err := os.Stat(path)
	if err != nil {
		return mode, uid, gid
	}
	mode = st.Mode().Perm()
	uid, gid = fileOwner(st)
	return mode, uid, gid
}

func applyFileIdent(path string, mode os.FileMode, uid, gid int) {
	_ = os.Chmod(path, mode)
	chownFile(path, uid, gid)
}
