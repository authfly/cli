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

func TestStoreConcurrentInviteCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	a, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	tokA, invA, err := a.CreateInvite(KindUser, "from-cli", time.Hour)
	if err != nil || tokA == "" {
		t.Fatal(err, invA)
	}
	got, err := b.PeekInvite(tokA)
	if err != nil || got.ID != invA.ID {
		t.Fatalf("server missed CLI invite: %v %+v", err, got)
	}
	tokB, invB, err := b.CreateInvite(KindOrg, "from-server", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	list := a.ListInvites()
	if len(list) != 2 {
		t.Fatalf("clobber: got %d invites %+v", len(list), list)
	}
	ids := map[string]bool{}
	for _, inv := range list {
		ids[inv.ID] = true
	}
	if !ids[invA.ID] || !ids[invB.ID] {
		t.Fatalf("missing invite %+v", list)
	}
	if _, err := a.PeekInvite(tokB); err != nil {
		t.Fatal(err)
	}
}

func TestInviteUnknown(t *testing.T) {
	st, _ := OpenStore(filepath.Join(t.TempDir(), "s.json"))
	if _, err := st.PeekInvite("no-such-token"); err != ErrBadInvite {
		t.Fatal(err)
	}
}
