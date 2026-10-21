package core

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Store keeps the little state Authkit owns (Stalwart owns accounts and passwords): which addresses are verified and
// which one-time tokens were used. A JSON file; swap for SQL/Redis by implementing the same methods.
type Store struct {
	Path string
	mu   sync.Mutex
	data storeData
}

type storeData struct {
	Verified map[string]int64 `json:"verified"`
	Used     map[string]int64 `json:"used"` // token id -> expiry
	// GDPR: consent records per address, and sessions issued before this time are revoked (erasure, sign out everywhere)
	Consents map[string][]Consent `json:"consents"`
	Revoked  map[string]int64     `json:"revoked"` // unix nanoseconds
}

// Consent is a record of a consent decision (Art. 7(1): the controller must be able to demonstrate consent).
type Consent struct {
	Kind    string   `json:"kind"`              // terms (sign-up), oidc (an application's access)
	Client  string   `json:"client,omitempty"`  // OIDC client id
	Scopes  []string `json:"scopes,omitempty"`  // OIDC scopes
	Version string   `json:"version,omitempty"` // terms version
	Granted bool     `json:"granted"`
	Time    string   `json:"time"`
}

func OpenStore(path string) (*Store, error) {
	s := &Store{Path: path, data: storeData{Verified: map[string]int64{}, Used: map[string]int64{}}}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &s.data)
	}
	if s.data.Verified == nil {
		s.data.Verified = map[string]int64{}
	}
	if s.data.Used == nil {
		s.data.Used = map[string]int64{}
	}
	if s.data.Consents == nil {
		s.data.Consents = map[string][]Consent{}
	}
	if s.data.Revoked == nil {
		s.data.Revoked = map[string]int64{}
	}
	return s, nil
}

func (s *Store) save() {
	if s.Path == "" {
		return
	}
	now := time.Now().Unix()
	for k, exp := range s.data.Used {
		if exp < now {
			delete(s.data.Used, k)
		}
	}
	b, _ := json.MarshalIndent(s.data, "", "  ")
	_ = os.WriteFile(s.Path+".tmp", b, 0o600)
	_ = os.Rename(s.Path+".tmp", s.Path)
}

func (s *Store) MarkVerified(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Verified[addr] = time.Now().Unix()
	s.save()
}

func (s *Store) IsVerified(addr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.data.Verified[addr]
	return ok
}

// Use marks a token id as used; false when it was used before.
func (s *Store) Use(id string, exp int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data.Used[id]; ok {
		return false
	}
	s.data.Used[id] = exp
	s.save()
	return true
}

func (s *Store) AddConsent(addr string, c Consent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.Time = time.Now().UTC().Format(time.RFC3339)
	s.data.Consents[addr] = append(s.data.Consents[addr], c)
	s.save()
}

func (s *Store) Consents(addr string) []Consent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Consent(nil), s.data.Consents[addr]...)
}

// Revoke invalidates every session of an address issued before now.
func (s *Store) Revoke(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Revoked[addr] = time.Now().UnixNano()
	s.save()
}

func (s *Store) RevokedAt(addr string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.data.Revoked[addr]; t > 0 {
		return t
	}
	return s.data.Revoked[Pseudonym(addr)]
}

// Forget removes everything Authkit keeps about an address (erasure) and keeps only the session revocation, keyed by
// the pseudonym, so a stolen session token cannot come back if the address is registered again.
func (s *Store) Forget(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data.Verified, addr)
	delete(s.data.Consents, addr)
	delete(s.data.Revoked, addr)
	s.data.Revoked[Pseudonym(addr)] = time.Now().UnixNano()
	s.save()
}

// Snapshot is what Authkit holds about an address (for the export).
func (s *Store) Snapshot(addr string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]any{"consents": s.data.Consents[addr]}
	if t, ok := s.data.Verified[addr]; ok {
		out["email_verified_at"] = time.Unix(t, 0).UTC().Format(time.RFC3339)
	}
	if t, ok := s.data.Revoked[addr]; ok {
		out["sessions_revoked_at"] = time.Unix(0, t).UTC().Format(time.RFC3339)
	}
	return out
}
