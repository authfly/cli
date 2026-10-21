package core

// Audit log: append-only JSON lines with a SHA-256 hash chain (each entry carries the hash of the previous one), so a
// removed or edited line breaks the chain (Verify). Data minimisation: no IP addresses, no passwords, no message
// content; the subject is the account address (pseudonymised to a hash once the account is erased).

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
)

type AuditEvent struct {
	Time    string            `json:"time"`
	Actor   string            `json:"actor"`   // "self", "console:<admin>", "system", or the client id
	Subject string            `json:"subject"` // account address (or "erased:<sha256>")
	Action  string            `json:"action"`  // sign_up, sign_in, sign_in_failed, magic_link, verify_email, password_reset, sign_out, consent, export, erase, console.*
	Outcome string            `json:"outcome"` // ok, denied, error
	Detail  map[string]string `json:"detail,omitempty"`
	Prev    string            `json:"prev"`
	Hash    string            `json:"hash"`
}

type Audit struct {
	Path string
	mu   sync.Mutex
	last string
}

func OpenAudit(path string) *Audit {
	a := &Audit{Path: path}
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var e AuditEvent
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				a.last = e.Hash
			}
		}
		f.Close()
	}
	return a
}

func hashEvent(e AuditEvent) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Log appends an event. Nil-safe.
func (a *Audit) Log(actor, subject, action, outcome string, detail map[string]string) {
	if a == nil || a.Path == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	e := AuditEvent{Time: time.Now().UTC().Format(time.RFC3339Nano), Actor: actor, Subject: subject, Action: action, Outcome: outcome, Detail: detail, Prev: a.last}
	e.Hash = hashEvent(e)
	b, _ := json.Marshal(e)
	f, err := os.OpenFile(a.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write(append(b, '\n'))
	f.Close()
	a.last = e.Hash
}

func (a *Audit) read() []AuditEvent {
	var out []AuditEvent
	f, err := os.Open(a.Path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e AuditEvent
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

// Query returns events, newest first; subject "" for all; limit 0 for no limit.
func (a *Audit) Query(subject string, limit int) []AuditEvent {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	all := a.read()
	a.mu.Unlock()
	var out []AuditEvent
	for i := len(all) - 1; i >= 0; i-- {
		if subject == "" || strings.EqualFold(all[i].Subject, subject) {
			out = append(out, all[i])
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out
}

// Verify checks the hash chain; it returns the number of entries and the index of the first broken one (-1: intact).
func (a *Audit) Verify() (int, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	all := a.read()
	prev := ""
	for i, e := range all {
		if (i > 0 && e.Prev != prev) || hashEvent(e) != e.Hash {
			return len(all), i
		}
		prev = e.Hash
	}
	return len(all), -1
}

// Pseudonymise rewrites the subject of an erased account to a hash; the chain is re-anchored and the rewrite logged.
// Retention prunes entries older than the cut-off the same way. Both rewrite the file atomically.
func (a *Audit) rewrite(keep func(*AuditEvent) bool) int {
	all := a.read()
	var out []AuditEvent
	changed := 0
	prev := ""
	for _, e := range all {
		before := e
		if !keep(&e) {
			changed++
			continue
		}
		if e.Subject != before.Subject {
			changed++
		}
		e.Prev = prev
		e.Hash = hashEvent(e)
		prev = e.Hash
		out = append(out, e)
	}
	var b strings.Builder
	for _, e := range out {
		j, _ := json.Marshal(e)
		b.Write(j)
		b.WriteByte('\n')
	}
	_ = os.WriteFile(a.Path+".tmp", []byte(b.String()), 0o600)
	_ = os.Rename(a.Path+".tmp", a.Path)
	a.last = prev
	return changed
}

func Pseudonym(addr string) string {
	h := sha256.Sum256([]byte(strings.ToLower(addr)))
	return "erased:" + hex.EncodeToString(h[:8])
}

func (a *Audit) Pseudonymise(addr string) int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	p := Pseudonym(addr)
	return a.rewrite(func(e *AuditEvent) bool {
		if strings.EqualFold(e.Subject, addr) {
			e.Subject = p
		}
		return true
	})
}

func (a *Audit) Prune(olderThan time.Duration) int {
	if a == nil || olderThan <= 0 {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cut := time.Now().Add(-olderThan).UTC().Format(time.RFC3339Nano)
	return a.rewrite(func(e *AuditEvent) bool { return e.Time >= cut })
}
