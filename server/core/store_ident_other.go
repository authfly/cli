//go:build !unix

package core

import "os"

func fileOwner(st os.FileInfo) (int, int) { return -1, -1 }
func chownFile(path string, uid, gid int) {}
