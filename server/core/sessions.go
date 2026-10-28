package core

import "time"

// SessionRec is one Authfly browser session of an account (internal id, never an email).
type SessionRec struct {
	ID        string `json:"id"`
	AccountID string `json:"accountId"`
	UserAgent string `json:"userAgent,omitempty"`
	Created   int64  `json:"created"`
}

// PutSession records a new session.
func (s *Store) PutSession(rec SessionRec) {
	s.do(true, func() {
		if s.data.Sessions == nil {
			s.data.Sessions = map[string][]SessionRec{}
		}
		if rec.Created == 0 {
			rec.Created = time.Now().Unix()
		}
		s.data.Sessions[rec.AccountID] = append(s.data.Sessions[rec.AccountID], rec)
	})
}

// SessionsOf lists sessions of an account id, newest first.
func (s *Store) SessionsOf(accountID string) []SessionRec {
	var out []SessionRec
	s.do(false, func() {
		in := s.data.Sessions[accountID]
		out = make([]SessionRec, len(in))
		copy(out, in)
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	})
	return out
}

// DropSession removes one session.
func (s *Store) DropSession(accountID, sessionID string) {
	s.do(true, func() {
		cur := s.data.Sessions[accountID]
		next := cur[:0]
		for _, rec := range cur {
			if rec.ID != sessionID {
				next = append(next, rec)
			}
		}
		if len(next) == 0 {
			delete(s.data.Sessions, accountID)
		} else {
			s.data.Sessions[accountID] = next
		}
	})
}

// DropSessions removes every session of an account (sign out everywhere).
func (s *Store) DropSessions(accountID string) {
	s.do(true, func() {
		delete(s.data.Sessions, accountID)
	})
}

// HasSession reports whether the session id is still recorded (false after sign-out-everywhere).
func (s *Store) HasSession(accountID, sessionID string) bool {
	found := false
	s.do(false, func() {
		for _, rec := range s.data.Sessions[accountID] {
			if rec.ID == sessionID {
				found = true
				return
			}
		}
	})
	return found
}
