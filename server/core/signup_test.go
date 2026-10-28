package core

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSignUpRequiresInvite(t *testing.T) {
	st, _ := OpenStore(filepath.Join(t.TempDir(), "s.json"))
	s := &Service{Cfg: Config{Domain: "cab.yself.link", UserDomainName: "cab.yself.link", PublicSignup: false}, Store: st}
	_, err := s.SignUpInvite(context.Background(), "Alice", "alice", "password-ok-long", "", KindUser)
	if err != ErrInviteRequired {
		t.Fatalf("%v", err)
	}
}

func TestSignUpBadInvite(t *testing.T) {
	st, _ := OpenStore(filepath.Join(t.TempDir(), "s.json"))
	s := &Service{Cfg: Config{Domain: "cab.yself.link", UserDomainName: "cab.yself.link"}, Store: st}
	_, err := s.SignUpInvite(context.Background(), "Alice", "alice", "password-ok-long", "nope", KindUser)
	if err != ErrBadInvite {
		t.Fatalf("%v", err)
	}
}

func TestSignUpReservedBeforeStalwart(t *testing.T) {
	st, _ := OpenStore(filepath.Join(t.TempDir(), "s.json"))
	tok, _, err := st.CreateInvite(KindUser, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{Cfg: Config{Domain: "cab.yself.link", UserDomainName: "cab.yself.link"}, Store: st}
	_, err = s.SignUpInvite(context.Background(), "Root", "admin", "password-ok-long", tok, KindUser)
	if err != ErrReservedName {
		t.Fatalf("%v", err)
	}
}
