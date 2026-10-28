package core

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

var (
	ErrInviteRequired = errors.New("an invite is required to create an account")
	ErrBadInvite      = errors.New("this invite is invalid, used, or expired")
	ErrReservedName   = errors.New("this username is reserved")
	ErrNameTaken      = errors.New("this username is taken")
	ErrExpired        = errors.New("this password has expired; reset it to continue")
)

// Invite is a single-use, expiring token that allows sign-up of one local-part kind.
type Invite struct {
	ID      string `json:"id"`
	Hash    string `json:"hash"`              // sha256 of the secret token (the secret is shown once)
	Kind    string `json:"kind"`              // KindUser | KindOrg
	Note    string `json:"note,omitempty"`    // operator memo, not shown to the invitee
	Created int64  `json:"created"`
	Expires int64  `json:"expires"`
	Used    int64  `json:"used,omitempty"`
	UsedBy  string `json:"usedBy,omitempty"` // account id, never an email
}

func hashInvite(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// CreateInvite records a new invite and returns the raw token (shown once) and the stored record.
func (s *Store) CreateInvite(kind, note string, ttl time.Duration) (token string, inv Invite, err error) {
	if kind != KindOrg {
		kind = KindUser
	}
	if ttl <= 0 {
		ttl = 72 * time.Hour
	}
	token = RandomString(24)
	now := time.Now().Unix()
	inv = Invite{
		ID:      RandomString(10),
		Hash:    hashInvite(token),
		Kind:    kind,
		Note:    note,
		Created: now,
		Expires: now + int64(ttl.Seconds()),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Invites == nil {
		s.data.Invites = map[string]Invite{}
	}
	s.data.Invites[inv.ID] = inv
	s.save()
	return token, inv, nil
}

// PeekInvite validates a token without consuming it.
func (s *Store) PeekInvite(token string) (*Invite, error) {
	if token == "" {
		return nil, ErrBadInvite
	}
	h := hashInvite(token)
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, inv := range s.data.Invites {
		if inv.Hash != h {
			continue
		}
		if inv.Used > 0 || inv.Expires < now {
			return nil, ErrBadInvite
		}
		inv.ID = id
		out := inv
		return &out, nil
	}
	return nil, ErrBadInvite
}

// ConsumeInvite marks the invite used by accountID (internal id, never an email).
func (s *Store) ConsumeInvite(token, accountID string) error {
	h := hashInvite(token)
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, inv := range s.data.Invites {
		if inv.Hash != h {
			continue
		}
		if inv.Used > 0 || inv.Expires < now {
			return ErrBadInvite
		}
		inv.Used = now
		inv.UsedBy = accountID
		s.data.Invites[id] = inv
		s.save()
		return nil
	}
	return ErrBadInvite
}

// ListInvites returns invites, newest first. Include used/expired.
func (s *Store) ListInvites() []Invite {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Invite, 0, len(s.data.Invites))
	for id, inv := range s.data.Invites {
		inv.ID = id
		out = append(out, inv)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Created > out[i].Created {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// RevokeInvite deletes an unused invite.
func (s *Store) RevokeInvite(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data.Invites[id]; !ok {
		return false
	}
	delete(s.data.Invites, id)
	s.save()
	return true
}
