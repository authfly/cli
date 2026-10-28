package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreSavePreservesModeAndOwner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.json")
	if err := os.WriteFile(path, []byte(`{"verified":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := fileOwner(before)
	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	st.MarkVerified("alice@cab.yself.link")
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != 0o640 {
		t.Fatalf("mode %o want 0640", after.Mode().Perm())
	}
	gotUID, gotGID := fileOwner(after)
	if uid >= 0 && (gotUID != uid || gotGID != gid) {
		t.Fatalf("owner %d:%d -> %d:%d", uid, gid, gotUID, gotGID)
	}
}

func TestApplyFileIdentPreservesMode(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "orig")
	tmp := filepath.Join(dir, "tmp")
	if err := os.WriteFile(orig, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(orig, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmp, []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	mode, uid, gid := fileIdent(orig)
	applyFileIdent(tmp, mode, uid, gid)
	st, err := os.Stat(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("tmp mode %o", st.Mode().Perm())
	}
	ou, og := fileOwner(mustStat(t, orig))
	tu, tg := fileOwner(st)
	if ou >= 0 && (tu != ou || tg != og) {
		t.Fatalf("tmp owner %d:%d want %d:%d", tu, tg, ou, og)
	}
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st
}
