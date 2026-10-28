package core

import (
	"path/filepath"
	"testing"
	"time"
)

func TestInviteRoundTrip(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "s.json"))
	if err != nil {
		t.Fatal(err)
	}
	tok, inv, err := st.CreateInvite(KindUser, "e2e", time.Hour)
	if err != nil || tok == "" || inv.ID == "" {
		t.Fatalf("%v %+v", err, inv)
	}
	got, err := st.PeekInvite(tok)
	if err != nil || got.Kind != KindUser {
		t.Fatal(err, got)
	}
	if err := st.ConsumeInvite(tok, "acc-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PeekInvite(tok); err != ErrBadInvite {
		t.Fatalf("reused: %v", err)
	}
	if err := st.ConsumeInvite(tok, "acc-2"); err != ErrBadInvite {
		t.Fatalf("consume twice: %v", err)
	}
}

func TestInviteExpired(t *testing.T) {
	st, _ := OpenStore(filepath.Join(t.TempDir(), "s.json"))
	tok, inv, _ := st.CreateInvite(KindOrg, "", time.Millisecond)
	st.mu.Lock()
	inv.Expires = 1
	st.data.Invites[inv.ID] = inv
	st.save()
	st.mu.Unlock()
	if _, err := st.PeekInvite(tok); err != ErrBadInvite {
		t.Fatalf("expired: %v", err)
	}
}

func TestInviteUnknown(t *testing.T) {
	st, _ := OpenStore(filepath.Join(t.TempDir(), "s.json"))
	if _, err := st.PeekInvite("no-such-token"); err != ErrBadInvite {
		t.Fatal(err)
	}
}
