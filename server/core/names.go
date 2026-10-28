package core

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

// Account kinds: a person mailbox lives on the user domain; an organisation or
// service account lives on the org domain. The local-part is unique across both.
const (
	KindUser = "user"
	KindOrg  = "org"
)

// DefaultReservedNames is used when AUTHFLY_RESERVED_NAMES_FILE is unset or unreadable.
var DefaultReservedNames = []string{
	"admin", "administrator", "wmaster", "webmaster", "postmaster", "hostmaster",
	"abuse", "security", "root", "noreply", "no-reply", "mailer-daemon", "mail",
	"www", "ftp", "ns", "ns1", "ns2", "mx", "smtp", "imap", "pop", "auth",
	"accounts", "account", "api", "support", "help", "info", "contact", "ssl-admin",
	"authfly", "stalwart", "yself", "system", "service", "svc", "operator", "owner",
	"login", "signin", "signup", "register", "oauth", "oidc", "openid", "sso",
	"localhost", "invalid", "example", "test", "guest", "anonymous", "nobody",
}

var (
	reservedMu   sync.RWMutex
	reservedSet  map[string]struct{}
	reservedOnce sync.Once
)

func initReserved(path string) {
	reservedOnce.Do(func() {
		reservedSet = map[string]struct{}{}
		for _, n := range DefaultReservedNames {
			reservedSet[strings.ToLower(n)] = struct{}{}
		}
		if path == "" {
			return
		}
		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			reservedSet[strings.ToLower(line)] = struct{}{}
		}
	})
}

// LoadReservedNames loads the reserved-names file (or the built-in list). Safe to call more than once;
// the first call wins.
func LoadReservedNames(path string) { initReserved(path) }

// IsReservedName reports whether the local-part is on the reserved list.
func IsReservedName(local string) bool {
	initReserved("")
	reservedMu.RLock()
	defer reservedMu.RUnlock()
	_, ok := reservedSet[strings.ToLower(strings.TrimSpace(local))]
	return ok
}

// Identity is a parsed account identifier (username or address).
type Identity struct {
	Local  string
	Domain string
	Kind   string // KindUser | KindOrg
}

// Address is local@domain.
func (id Identity) Address() string { return id.Local + "@" + id.Domain }

// MirrorDomain is the other domain of the shared name namespace.
func (s *Service) MirrorDomain(domain string) string {
	u, o := strings.ToLower(s.Cfg.UserDomain()), strings.ToLower(s.Cfg.OrgDomain())
	switch strings.ToLower(domain) {
	case u:
		return o
	case o:
		if o != u {
			return u
		}
	}
	return ""
}

// UserDomain is the domain of person mailboxes (AUTHFLY_USER_DOMAIN, else AUTHFLY_DOMAIN).
func (c Config) UserDomain() string {
	if c.UserDomainName != "" {
		return c.UserDomainName
	}
	return c.Domain
}

// OrgDomain is the domain of organisation / service accounts. Empty: single-domain mode.
func (c Config) OrgDomain() string {
	if c.OrgDomainName != "" {
		return c.OrgDomainName
	}
	return ""
}

// Domains is the list of mail domains Authfly manages (user, and org when set and different).
func (c Config) Domains() []string {
	u := c.UserDomain()
	out := []string{u}
	if o := c.OrgDomain(); o != "" && !strings.EqualFold(o, u) {
		out = append(out, o)
	}
	return out
}

// ParseMethods splits AUTHFLY_METHODS (comma list). Empty input means password+magic.
func ParseMethods(list string) []string {
	var out []string
	for _, m := range strings.Split(list, ",") {
		m = strings.TrimSpace(strings.ToLower(m))
		if m == "" {
			continue
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return []string{"password", "magic"}
	}
	return out
}

// HasMethod reports whether a sign-in method is enabled. Empty Methods means password+magic.
func (c Config) HasMethod(name string) bool {
	ms := c.Methods
	if len(ms) == 0 {
		ms = []string{"password", "magic"}
	}
	for _, m := range ms {
		if m == name {
			return true
		}
	}
	return false
}

func (c Config) kindOfDomain(domain string) string {
	if o := c.OrgDomain(); o != "" && strings.EqualFold(domain, o) {
		return KindOrg
	}
	return KindUser
}
