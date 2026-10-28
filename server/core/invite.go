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
	Hash    string `json:"hash"`           // sha256 of the secret token (the secret is shown once)
	Kind    string `json:"kind"`           // KindUser | KindOrg
	Note    string `json:"note,omitempty"` // operator memo, not shown to the invitee
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
	s.do(true, func() {
		if s.data.Invites == nil {
			s.data.Invites = map[string]Invite{}
		}
		s.data.Invites[inv.ID] = inv
	})
	return token, inv, nil
}

// PeekInvite validates a token without consuming it.
func (s *Store) PeekInvite(token string) (*Invite, error) {
	if token == "" {
		return nil, ErrBadInvite
	}
	h := hashInvite(token)
	now := time.Now().Unix()
	var out *Invite
	var err error = ErrBadInvite
	s.do(false, func() {
		for id, inv := range s.data.Invites {
			if inv.Hash != h {
				continue
			}
			if inv.Used > 0 || inv.Expires < now {
				err = ErrBadInvite
				return
			}
			inv.ID = id
			cp := inv
			out = &cp
			err = nil
			return
		}
	})
	return out, err
}

// ConsumeInvite marks the invite used by accountID (internal id, never an email).
func (s *Store) ConsumeInvite(token, accountID string) error {
	h := hashInvite(token)
	now := time.Now().Unix()
	err := ErrBadInvite
	s.do(true, func() {
		for id, inv := range s.data.Invites {
			if inv.Hash != h {
				continue
			}
			if inv.Used > 0 || inv.Expires < now {
				err = ErrBadInvite
				return
			}
			inv.Used = now
			inv.UsedBy = accountID
			s.data.Invites[id] = inv
			err = nil
			return
		}
	})
	return err
}

// ListInvites returns invites, newest first. Include used/expired.
func (s *Store) ListInvites() []Invite {
	var out []Invite
	s.do(false, func() {
		out = make([]Invite, 0, len(s.data.Invites))
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
	})
	return out
}

// RevokeInvite deletes an unused invite.
func (s *Store) RevokeInvite(id string) bool {
	ok := false
	s.do(true, func() {
		if _, exists := s.data.Invites[id]; !exists {
			return
		}
		delete(s.data.Invites, id)
		ok = true
	})
	return ok
}
