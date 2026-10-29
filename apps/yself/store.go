package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/authfly/cli/server/rp"
)

// Profile is one public page: yself.link/<handle>.
type Profile struct {
	Sub, Handle, Name, Bio, Avatar string
	Theme, Buttons, Shape          string
	Updated                        int64
}

// Link is one button on a profile.
type Link struct {
	ID              int64
	Pos             int
	Title, URL, Icon string
	Enabled         bool
}

// Store persists profiles and links in SQLite (WAL, one file under the state directory).
type Store struct{ db *sql.DB }

var ErrTaken = errors.New("handle taken")

const schema = `
CREATE TABLE IF NOT EXISTS profiles (
	sub TEXT PRIMARY KEY,
	handle TEXT NOT NULL UNIQUE,
	name TEXT NOT NULL DEFAULT '',
	bio TEXT NOT NULL DEFAULT '',
	avatar TEXT NOT NULL DEFAULT '',
	theme TEXT NOT NULL DEFAULT 'light',
	buttons TEXT NOT NULL DEFAULT 'solid',
	shape TEXT NOT NULL DEFAULT 'rounded',
	updated INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS links (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	sub TEXT NOT NULL REFERENCES profiles(sub) ON DELETE CASCADE,
	pos INTEGER NOT NULL,
	title TEXT NOT NULL,
	url TEXT NOT NULL,
	icon TEXT NOT NULL DEFAULT '',
	enabled INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS links_sub ON links(sub, pos);
CREATE TABLE IF NOT EXISTS sessions (
	key TEXT PRIMARY KEY,
	data TEXT NOT NULL,
	expires INTEGER NOT NULL
);
`

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer; reads are tiny
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

const profCols = "sub, handle, name, bio, avatar, theme, buttons, shape, updated"

func scanProfile(row interface{ Scan(...any) error }) (*Profile, error) {
	p := &Profile{}
	if err := row.Scan(&p.Sub, &p.Handle, &p.Name, &p.Bio, &p.Avatar, &p.Theme, &p.Buttons, &p.Shape, &p.Updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return p, nil
}

func (s *Store) BySub(sub string) (*Profile, error) {
	return scanProfile(s.db.QueryRow("SELECT "+profCols+" FROM profiles WHERE sub = ?", sub))
}

func (s *Store) ByHandle(h string) (*Profile, error) {
	return scanProfile(s.db.QueryRow("SELECT "+profCols+" FROM profiles WHERE handle = ?", strings.ToLower(h)))
}

func isUnique(err error) bool { return err != nil && strings.Contains(err.Error(), "UNIQUE") }

// Create inserts a new profile; ErrTaken when the handle exists.
func (s *Store) Create(p *Profile) error {
	p.Updated = time.Now().Unix()
	_, err := s.db.Exec("INSERT INTO profiles ("+profCols+") VALUES (?,?,?,?,?,?,?,?,?)", p.Sub, p.Handle, p.Name, p.Bio, p.Avatar, p.Theme, p.Buttons, p.Shape, p.Updated)
	if isUnique(err) {
		return ErrTaken
	}
	return err
}

// Save updates handle, texts and style; ErrTaken when the new handle belongs to someone else.
func (s *Store) Save(p *Profile) error {
	p.Updated = time.Now().Unix()
	_, err := s.db.Exec("UPDATE profiles SET handle=?, name=?, bio=?, theme=?, buttons=?, shape=?, updated=? WHERE sub=?", p.Handle, p.Name, p.Bio, p.Theme, p.Buttons, p.Shape, p.Updated, p.Sub)
	if isUnique(err) {
		return ErrTaken
	}
	return err
}

func (s *Store) SetAvatar(sub, file string) error {
	_, err := s.db.Exec("UPDATE profiles SET avatar=?, updated=? WHERE sub=?", file, time.Now().Unix(), sub)
	return err
}

func (s *Store) Links(sub string, onlyEnabled bool) ([]Link, error) {
	q := "SELECT id, pos, title, url, icon, enabled FROM links WHERE sub = ?"
	if onlyEnabled {
		q += " AND enabled = 1"
	}
	rows, err := s.db.Query(q+" ORDER BY pos, id", sub)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Link
	for rows.Next() {
		var l Link
		if err := rows.Scan(&l.ID, &l.Pos, &l.Title, &l.URL, &l.Icon, &l.Enabled); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) CountLinks(sub string) (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM links WHERE sub = ?", sub).Scan(&n)
	return n, err
}

func (s *Store) AddLink(sub string, l Link) error {
	_, err := s.db.Exec("INSERT INTO links (sub, pos, title, url, icon, enabled) VALUES (?, COALESCE((SELECT MAX(pos)+1 FROM links WHERE sub=?),0), ?, ?, ?, ?)",
		sub, sub, l.Title, l.URL, l.Icon, l.Enabled)
	return err
}

// UpdateLink changes one of the owner's links (the WHERE on sub keeps users out of each other's rows).
func (s *Store) UpdateLink(sub string, l Link) (bool, error) {
	r, err := s.db.Exec("UPDATE links SET title=?, url=?, icon=?, enabled=? WHERE id=? AND sub=?", l.Title, l.URL, l.Icon, l.Enabled, l.ID, sub)
	if err != nil {
		return false, err
	}
	n, _ := r.RowsAffected()
	return n == 1, nil
}

func (s *Store) DeleteLink(sub string, id int64) (bool, error) {
	r, err := s.db.Exec("DELETE FROM links WHERE id=? AND sub=?", id, sub)
	if err != nil {
		return false, err
	}
	n, _ := r.RowsAffected()
	return n == 1, nil
}

// MoveLink swaps a link with its neighbour (dir -1 up, +1 down) and renumbers positions 0..n-1.
func (s *Store) MoveLink(sub string, id int64, dir int) error {
	ls, err := s.Links(sub, false)
	if err != nil {
		return err
	}
	i := -1
	for k, l := range ls {
		if l.ID == id {
			i = k
		}
	}
	j := i + dir
	if i < 0 || j < 0 || j >= len(ls) {
		return nil
	}
	ls[i], ls[j] = ls[j], ls[i]
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for k, l := range ls {
		if _, err := tx.Exec("UPDATE links SET pos=? WHERE id=? AND sub=?", k, l.ID, sub); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// rp.SessionStore: browser sessions survive restarts and deploys (key = SHA-256 of the cookie value).

func (s *Store) LoadSessions() (map[string]*rp.Session, error) {
	now := time.Now().Unix()
	if _, err := s.db.Exec("DELETE FROM sessions WHERE expires <= ?", now); err != nil {
		return nil, err
	}
	rows, err := s.db.Query("SELECT key, data FROM sessions")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*rp.Session{}
	for rows.Next() {
		var k, d string
		if err := rows.Scan(&k, &d); err != nil {
			return nil, err
		}
		var ss rp.Session
		if json.Unmarshal([]byte(d), &ss) == nil {
			out[k] = &ss
		}
	}
	return out, rows.Err()
}

func (s *Store) SaveSession(key string, ss *rp.Session) error {
	d, err := json.Marshal(ss)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("INSERT OR REPLACE INTO sessions (key, data, expires) VALUES (?, ?, ?)", key, string(d), ss.Expires.Unix())
	return err
}

func (s *Store) DeleteSession(key string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE key = ?", key)
	return err
}
