package core

import "os"

func (s *Store) acquireFileLock() *os.File {
	if s.Path == "" {
		return nil
	}
	f, err := os.OpenFile(s.Path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil
	}
	return f
}

func (s *Store) releaseFileLock(f *os.File) {
	if f == nil {
		return
	}
	_ = unlockFile(f)
	_ = f.Close()
}
