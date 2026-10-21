package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	a := OpenAudit(p)
	a.Log("self", "x@d", "sign_up", "ok", nil)
	a.Log("self", "y@d", "sign_in", "ok", nil)
	a.Log("self", "x@d", "sign_in", "ok", map[string]string{"method": "password"})
	if n, b := a.Verify(); n != 3 || b != -1 {
		t.Fatalf("verify %d %d", n, b)
	}
	if got := len(a.Query("x@d", 0)); got != 2 {
		t.Fatalf("query %d", got)
	}
	// reopen continues the chain
	a2 := OpenAudit(p)
	a2.Log("system", "", "retention", "ok", nil)
	if _, b := a2.Verify(); b != -1 {
		t.Fatal("chain broken after reopen")
	}
	// tampering is detected
	raw, _ := os.ReadFile(p)
	_ = os.WriteFile(p, []byte(strings.Replace(string(raw), "y@d", "z@d", 1)), 0o600)
	if _, b := a2.Verify(); b != 1 {
		t.Fatalf("tamper not detected: %d", b)
	}
	_ = os.WriteFile(p, raw, 0o600)
	// pseudonymisation removes the address and keeps the chain valid
	if n := a2.Pseudonymise("x@d"); n != 2 {
		t.Fatalf("pseudonymised %d", n)
	}
	raw, _ = os.ReadFile(p)
	if strings.Contains(string(raw), "x@d") {
		t.Fatal("address still present")
	}
	if _, b := a2.Verify(); b != -1 {
		t.Fatal("chain broken after pseudonymise")
	}
	if len(a2.Query(Pseudonym("x@d"), 0)) != 2 {
		t.Fatal("pseudonym query")
	}
	time.Sleep(5 * time.Millisecond)
	if n := a2.Prune(time.Millisecond); n != 4 {
		t.Fatalf("pruned %d", n)
	}
}

func TestStoreForget(t *testing.T) {
	s, _ := OpenStore(filepath.Join(t.TempDir(), "s.json"))
	s.MarkVerified("x@d")
	s.AddConsent("x@d", Consent{Kind: "terms", Granted: true})
	s.Forget("x@d")
	if s.IsVerified("x@d") || len(s.Consents("x@d")) != 0 || s.RevokedAt("x@d") == 0 {
		t.Fatal("forget")
	}
	raw, _ := os.ReadFile(s.Path)
	if strings.Contains(string(raw), "x@d") {
		t.Fatal("address kept in store")
	}
}
