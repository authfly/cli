package core

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Store keeps the little state Authfly owns (Stalwart owns accounts and passwords): which addresses are verified and
// which one-time tokens were used. A JSON file; swap for SQL/Redis by implementing the same methods.
//
// Concurrent CLI + server: every read/write takes an exclusive flock on AUTHFLY_STORE.lock, reloads the file, then
// (on write) saves. `authfly invite create` while `authfly serve` is running is therefore safe as long as both use
// the same AUTHFLY_STORE path. Do not copy or replace the JSON file by hand while a process holds the lock.
type Store struct {
	Path string
	mu   sync.Mutex
	data storeData
}

type storeData struct {
	Verified map[string]int64 `json:"verified"`
	Used     map[string]int64 `json:"used"` // token id -> expiry
	// GDPR: consent records per address, and sessions issued before this time are revoked (erasure, sign out everywhere)
	Consents map[string][]Consent    `json:"consents"`
	Revoked  map[string]int64        `json:"revoked"` // unix nanoseconds
	Invites  map[string]Invite       `json:"invites,omitempty"`
	Sessions map[string][]SessionRec `json:"sessions,omitempty"` // account id -> sessions
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
	s := &Store{Path: path, data: storeData{}}
	s.ensureMaps()
	if path != "" {
		s.mu.Lock()
		lf := s.acquireFileLock()
		s.reload()
		s.releaseFileLock(lf)
		s.mu.Unlock()
	}
	return s, nil
}

func (s *Store) ensureMaps() {
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
	if s.data.Invites == nil {
		s.data.Invites = map[string]Invite{}
	}
	if s.data.Sessions == nil {
		s.data.Sessions = map[string][]SessionRec{}
	}
}

func (s *Store) reload() {
	if s.Path == "" {
		return
	}
	b, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	var d storeData
	if json.Unmarshal(b, &d) != nil {
		return
	}
	s.data = d
	s.ensureMaps()
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
	mode, uid, gid := fileIdent(s.Path)
	tmp := s.Path + ".tmp"
	if os.WriteFile(tmp, b, mode) != nil {
		return
	}
	applyFileIdent(tmp, mode, uid, gid)
	_ = os.Rename(tmp, s.Path)
}

// do takes the process mutex and the inter-process file lock, reloads from disk, runs fn, and writes if write.
func (s *Store) do(write bool, fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lf := s.acquireFileLock()
	defer s.releaseFileLock(lf)
	s.reload()
	fn()
	if write {
		s.save()
	}
}

func (s *Store) MarkVerified(addr string) {
	s.do(true, func() {
		s.data.Verified[addr] = time.Now().Unix()
	})
}

func (s *Store) IsVerified(addr string) bool {
	var ok bool
	s.do(false, func() {
		_, ok = s.data.Verified[addr]
	})
	return ok
}

// Use marks a token id as used; false when it was used before.
func (s *Store) Use(id string, exp int64) bool {
	ok := true
	s.do(true, func() {
		if _, taken := s.data.Used[id]; taken {
			ok = false
			return
		}
		s.data.Used[id] = exp
	})
	return ok
}

func (s *Store) AddConsent(addr string, c Consent) {
	s.do(true, func() {
		c.Time = time.Now().UTC().Format(time.RFC3339)
		s.data.Consents[addr] = append(s.data.Consents[addr], c)
	})
}

func (s *Store) Consents(addr string) []Consent {
	var out []Consent
	s.do(false, func() {
		out = append([]Consent(nil), s.data.Consents[addr]...)
	})
	return out
}

// Revoke invalidates every session of an address issued before now.
func (s *Store) Revoke(addr string) {
	s.do(true, func() {
		s.data.Revoked[addr] = time.Now().UnixNano()
	})
}

func (s *Store) RevokedAt(addr string) int64 {
	var t int64
	s.do(false, func() {
		if v := s.data.Revoked[addr]; v > 0 {
			t = v
			return
		}
		t = s.data.Revoked[Pseudonym(addr)]
	})
	return t
}

func (s *Store) forgetLocked(addr string) {
	delete(s.data.Verified, addr)
	delete(s.data.Consents, addr)
	delete(s.data.Revoked, addr)
	s.data.Revoked[Pseudonym(addr)] = time.Now().UnixNano()
}

// Forget removes everything Authfly keeps about an address (erasure) and keeps only the session revocation, keyed by
// the pseudonym, so a stolen session token cannot come back if the address is registered again.
func (s *Store) Forget(addr string) {
	s.do(true, func() { s.forgetLocked(addr) })
}

// ForgetAccount is Forget keyed by address plus drop of sessions of the account id.
func (s *Store) ForgetAccount(addr, accountID string) {
	s.do(true, func() {
		s.forgetLocked(addr)
		delete(s.data.Sessions, accountID)
	})
}

// Snapshot is what Authfly holds about an address (for the export).
func (s *Store) Snapshot(addr string) map[string]any {
	var out map[string]any
	s.do(false, func() {
		out = map[string]any{"consents": s.data.Consents[addr]}
		if t, ok := s.data.Verified[addr]; ok {
			out["email_verified_at"] = time.Unix(t, 0).UTC().Format(time.RFC3339)
		}
		if t, ok := s.data.Revoked[addr]; ok {
			out["sessions_revoked_at"] = time.Unix(0, t).UTC().Format(time.RFC3339)
		}
	})
	return out
}
