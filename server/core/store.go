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
