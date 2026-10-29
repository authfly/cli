// Package idp makes Authfly its own OpenID Connect provider (issuer) on top of zitadel/oidc's op package: Authfly
// owns the ES256 signing keys, the SSO session, authorization codes, access and refresh tokens, per-client grants
// and back-channel logout. Credentials stay in Stalwart (verified through the core service's /api/auth adapter);
// the subject stays the Stalwart account id.
package idp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Session is one SSO browser session on the issuer (sid == the portal session id behind the authfly_session cookie).
type Session struct {
	SID       string            `json:"sid"`
	Sub       string            `json:"sub"`
	UserAgent string            `json:"ua,omitempty"`
	IP        string            `json:"ip,omitempty"`
	AuthTime  time.Time         `json:"authTime"`
	Created   time.Time         `json:"created"`
	LastSeen  time.Time         `json:"lastSeen"`
	AMR       []string          `json:"amr,omitempty"`
	Clients   map[string]*Grant `json:"clients,omitempty"` // client id -> use of this client in this session
}

// Grant records a client's use by a user (consent remembered per client; first/last sign-in, scopes).
type Grant struct {
	ClientID string    `json:"clientId"`
	Scopes   []string  `json:"scopes,omitempty"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
}

// Profile is the userinfo snapshot taken at sign-in from Stalwart (admin JMAP).
type Profile struct {
	Sub, Username, Name, Email string
	EmailVerified              bool
}

// Token is an opaque access token (its id is the bearer value).
type Token struct {
	ID, ClientID, Subject, SID, RefreshToken string
	Audience, Scopes, AMR                    []string
	AuthTime, Expiration                     time.Time
}

// Refresh is a refresh token (rotated on use).
type Refresh struct {
	Token, AccessID, ClientID, Subject, SID string
	Audience, Scopes, AMR                   []string
	AuthTime, Expiration                    time.Time
}

type data struct {
	AuthRequests map[string]*AuthRequest `json:"authRequests"`
	Codes        map[string]string       `json:"codes"`
	Tokens       map[string]*Token       `json:"tokens"`
	Refresh      map[string]*Refresh     `json:"refresh"`
	Sessions     map[string]*Session     `json:"sessions"`
	Grants       map[string]*Grant       `json:"grants"` // sub|client
	Profiles     map[string]*Profile     `json:"profiles"`
}

// Store persists the provider state in one JSON file (atomic rename on every write), like core.Store.
type Store struct {
	path string
	mu   sync.Mutex
	d    data
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			if err := json.Unmarshal(b, &s.d); err != nil {
				return nil, err
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	s.init()
	return s, nil
}

func (s *Store) init() {
	if s.d.AuthRequests == nil {
		s.d.AuthRequests = map[string]*AuthRequest{}
	}
	if s.d.Codes == nil {
		s.d.Codes = map[string]string{}
	}
	if s.d.Tokens == nil {
		s.d.Tokens = map[string]*Token{}
	}
	if s.d.Refresh == nil {
		s.d.Refresh = map[string]*Refresh{}
	}
	if s.d.Sessions == nil {
		s.d.Sessions = map[string]*Session{}
	}
	if s.d.Grants == nil {
		s.d.Grants = map[string]*Grant{}
	}
	if s.d.Profiles == nil {
		s.d.Profiles = map[string]*Profile{}
	}
}

// tx runs fn under the lock and saves when write is set.
func (s *Store) tx(write bool, fn func(d *data)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.d)
	if write {
		s.saveLocked()
	}
}

func (s *Store) saveLocked() {
	if s.path == "" {
		return
	}
	now := time.Now()
	for id, a := range s.d.AuthRequests {
		if now.Sub(a.CreationDate) > 30*time.Minute {
			delete(s.d.AuthRequests, id)
			delete(s.d.Codes, a.Code)
		}
	}
	for id, t := range s.d.Tokens {
		if now.After(t.Expiration) {
			delete(s.d.Tokens, id)
		}
	}
	for id, t := range s.d.Refresh {
		if now.After(t.Expiration) {
			delete(s.d.Refresh, id)
		}
	}
	b, _ := json.Marshal(&s.d)
	tmp := s.path + ".tmp"
	_ = os.MkdirAll(filepath.Dir(s.path), 0o700)
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, s.path)
	}
}

func grantKey(sub, client string) string { return sub + "|" + client }

// PutSession registers (or refreshes) an SSO session.
func (s *Store) PutSession(ss *Session) {
	s.tx(true, func(d *data) {
		if old := d.Sessions[ss.SID]; old != nil && ss.Clients == nil {
			ss.Clients = old.Clients
		}
		if ss.Clients == nil {
			ss.Clients = map[string]*Grant{}
		}
		d.Sessions[ss.SID] = ss
	})
}

func (s *Store) Session(sid string) *Session {
	var out *Session
	s.tx(false, func(d *data) {
		if v := d.Sessions[sid]; v != nil {
			c := *v
			out = &c
		}
	})
	return out
}

// Touch updates last-seen of a session.
func (s *Store) Touch(sid string) {
	s.tx(true, func(d *data) {
		if v := d.Sessions[sid]; v != nil {
			v.LastSeen = time.Now()
		}
	})
}

// SessionsOf lists a user's sessions, newest first.
func (s *Store) SessionsOf(sub string) []Session {
	var out []Session
	s.tx(false, func(d *data) {
		for _, v := range d.Sessions {
			if v.Sub == sub {
				out = append(out, *v)
			}
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// GrantsOf lists the clients a user has signed in to.
func (s *Store) GrantsOf(sub string) []Grant {
	var out []Grant
	s.tx(false, func(d *data) {
		for k, g := range d.Grants {
			if strings.HasPrefix(k, sub+"|") {
				out = append(out, *g)
			}
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	return out
}

// HasGrant tells whether the user already consented to the client.
func (s *Store) HasGrant(sub, client string) bool {
	ok := false
	s.tx(false, func(d *data) { _, ok = d.Grants[grantKey(sub, client)] })
	return ok
}

// recordUse notes a sign-in of sub to client within sid.
func (s *Store) recordUse(sub, sid, client string, scopes []string) {
	now := time.Now()
	s.tx(true, func(d *data) {
		g := d.Grants[grantKey(sub, client)]
		if g == nil {
			g = &Grant{ClientID: client, First: now}
			d.Grants[grantKey(sub, client)] = g
		}
		g.Last, g.Scopes = now, scopes
		if ss := d.Sessions[sid]; ss != nil {
			if ss.Clients == nil {
				ss.Clients = map[string]*Grant{}
			}
			sg := ss.Clients[client]
			if sg == nil {
				sg = &Grant{ClientID: client, First: now}
				ss.Clients[client] = sg
			}
			sg.Last, sg.Scopes = now, scopes
			ss.LastSeen = now
		}
	})
}

func (s *Store) PutProfile(p *Profile) {
	s.tx(true, func(d *data) { d.Profiles[p.Sub] = p })
}

func (s *Store) Profile(sub string) *Profile {
	var out *Profile
	s.tx(false, func(d *data) {
		if p := d.Profiles[sub]; p != nil {
			c := *p
			out = &c
		}
	})
	return out
}

// revokeLocked deletes tokens matching f.
func revokeLocked(d *data, f func(client, sub, sid string) bool) {
	for id, t := range d.Tokens {
		if f(t.ClientID, t.Subject, t.SID) {
			delete(d.Tokens, id)
		}
	}
	for id, t := range d.Refresh {
		if f(t.ClientID, t.Subject, t.SID) {
			delete(d.Refresh, id)
		}
	}
}

// RemoveClientFromSession revokes a client's tokens in one session and forgets the client there (RP-initiated
// logout from that client: the SSO session and the other clients stay).
func (s *Store) RemoveClientFromSession(sid, client string) {
	s.tx(true, func(d *data) {
		revokeLocked(d, func(c, _, ts string) bool { return c == client && ts == sid })
		if ss := d.Sessions[sid]; ss != nil {
			delete(ss.Clients, client)
		}
	})
}

// RevokeClient revokes a client entirely for a user (tokens in every session, the grant/consent) and returns the
// sessions the client was signed in to (for back-channel logout).
func (s *Store) RevokeClient(sub, client string) []string {
	var sids []string
	s.tx(true, func(d *data) {
		revokeLocked(d, func(c, u, _ string) bool { return c == client && u == sub })
		delete(d.Grants, grantKey(sub, client))
		for _, ss := range d.Sessions {
			if ss.Sub == sub {
				if _, ok := ss.Clients[client]; ok {
					sids = append(sids, ss.SID)
					delete(ss.Clients, client)
				}
			}
		}
	})
	return sids
}

// DeleteSession destroys an SSO session and its tokens; returns the deleted record (with its clients).
func (s *Store) DeleteSession(sid string) *Session {
	var out *Session
	s.tx(true, func(d *data) {
		out = d.Sessions[sid]
		delete(d.Sessions, sid)
		revokeLocked(d, func(_, _, ts string) bool { return ts == sid })
	})
	return out
}

// AuthRequest returns a copy of a pending authorization request.
func (s *Store) AuthRequest(id string) *AuthRequest {
	var out *AuthRequest
	s.tx(false, func(d *data) {
		if a := d.AuthRequests[id]; a != nil {
			c := *a
			out = &c
		}
	})
	return out
}

// CompleteAuthRequest binds a pending request to an authenticated SSO session.
func (s *Store) CompleteAuthRequest(id, sub, sid string, amr []string, authTime time.Time) bool {
	ok := false
	s.tx(true, func(d *data) {
		if a := d.AuthRequests[id]; a != nil {
			a.Subject, a.SID, a.AMR, a.AuthTime, a.IsDone = sub, sid, amr, authTime, true
			ok = true
		}
	})
	return ok
}
