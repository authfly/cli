// Package deploy is the Authfly deployment system behind `npx authfly` / the authfly binary: one declarative
// authfly.yaml (source of truth), generated secrets (0600, never printed), policy packs, and idempotent drivers for
// Docker Compose and Incus.
package deploy

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Runtimes are the widget runtimes; Adapters the server adapters (docs/deploy.md).
var (
	Runtimes = []string{"react", "vue", "svelte", "solid", "templ", "twig", "latte", "jinja2"}
	Adapters = []string{"node", "bun", "php", "python", "go"}
	Policies = []string{"none", "gdpr", "us-pii", "ru-152fz"}
	Targets  = []string{"docker", "incus"}
)

type Client struct {
	ID           string   `yaml:"id" json:"id"`
	Name         string   `yaml:"name" json:"name"`
	RedirectURIs []string `yaml:"redirect_uris" json:"redirect_uris"`
}

type Config struct {
	Version int    `yaml:"version"`
	Name    string `yaml:"name"`   // instance name: compose project / incus prefix
	Target  string `yaml:"target"` // docker | incus
	App     struct {
		Runtime string   `yaml:"runtime"` // widget runtime
		Adapter string   `yaml:"adapter"` // server adapter
		Clients []Client `yaml:"clients"` // OIDC relying parties
	} `yaml:"app"`
	Domain    string `yaml:"domain"`     // mail domain of the accounts (user@domain)
	PublicURL string `yaml:"public_url"` // Authfly public URL = OIDC issuer
	HTTP      struct {
		Port     int    `yaml:"port"`      // public port of Authfly (443 with TLS)
		HTTPPort int    `yaml:"http_port"` // ACME HTTP-01 + redirect (80); 0 = off
		TLS      string `yaml:"tls"`       // acme | manual | off
		CertFile string `yaml:"cert_file,omitempty"`
		KeyFile  string `yaml:"key_file,omitempty"`
		ACMEMail string `yaml:"acme_email,omitempty"`
	} `yaml:"http"`
	Mail struct {
		Hostname         string `yaml:"hostname"`
		TLS              string `yaml:"tls"`     // acme | manual | off (mail ports keep STARTTLS/implicit TLS with Stalwart's self-signed cert when off)
		Storage          string `yaml:"storage"` // rocksdb (only one wired so far)
		EncryptionAtRest bool   `yaml:"encryption_at_rest"`
		Ports            struct {
			SMTP        int `yaml:"smtp"`
			Submissions int `yaml:"submissions"`
			IMAPS       int `yaml:"imaps"`
		} `yaml:"ports"`
	} `yaml:"mail"`
	SignIn struct {
		MagicLink     bool `yaml:"magic_link"`
		Password      bool `yaml:"password"`       // email + password
		Username      bool `yaml:"username"`       // username + password (the local part)
		Social        bool `yaml:"social"`         // coming
		TwoFactor     bool `yaml:"two_factor"`     // coming
		WebAuthn      bool `yaml:"webauthn"`       // coming
		RequireVerify bool `yaml:"require_verify"` // email verification before first sign-in
	} `yaml:"sign_in"`
	Policy struct {
		Pack        string   `yaml:"pack"`                   // none | gdpr | us-pii | ru-152fz
		Operator    string   `yaml:"operator"`               // controller / business / operator legal name
		Contact     string   `yaml:"contact"`                // privacy contact email
		USStates    []string `yaml:"us_states,omitempty"`    // us-pii: state laws in scope (CA verified; others marked)
		Residency   string   `yaml:"residency,omitempty"`    // ISO country the data must stay in (RU for 152-FZ)
		HostCountry string   `yaml:"host_country,omitempty"` // where the server physically is (declared by you, checked by doctor)
	} `yaml:"policy"`
	Ports struct { // localhost-only management ports on the host
		Management int `yaml:"management"` // Stalwart HTTP (JMAP management) on 127.0.0.1
		Console    int `yaml:"console"`    // Authfly Console on 127.0.0.1
	} `yaml:"ports"`
	Channel struct {
		Name     string `yaml:"name"`     // stable
		Manifest string `yaml:"manifest"` // URL or file of channel.json
		Version  string `yaml:"version"`  // pinned release; empty = latest in channel
	} `yaml:"channel"`
	Incus struct {
		Network  string `yaml:"network"` // private bridge
		Subnet   string `yaml:"subnet"`  // e.g. 10.118.42.1/24
		Pool     string `yaml:"pool"`
		Image    string `yaml:"image"`    // base system image
		Firewall bool   `yaml:"firewall"` // write and load /etc/nftables.d/authfly-<name>.nft
	} `yaml:"incus"`
	Backup struct {
		Dir  string `yaml:"dir"`
		Keep int    `yaml:"keep"`
	} `yaml:"backup"`

	path string `yaml:"-"`
}

// Defaults fills every unset field with the secure default.
func (c *Config) Defaults() {
	def := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	defi := func(p *int, v int) {
		if *p == 0 {
			*p = v
		}
	}
	if c.Version == 0 {
		c.Version = 1
	}
	def(&c.Name, "authfly")
	def(&c.Target, "docker")
	def(&c.App.Runtime, "react")
	def(&c.App.Adapter, "node")
	def(&c.Domain, "example.com")
	def(&c.PublicURL, "https://auth."+c.Domain)
	def(&c.HTTP.TLS, "acme")
	if c.HTTP.TLS == "off" {
		defi(&c.HTTP.Port, 4000)
	} else {
		defi(&c.HTTP.Port, 443)
		if c.HTTP.TLS == "acme" {
			defi(&c.HTTP.HTTPPort, 80)
		}
	}
	def(&c.Mail.Hostname, "mail."+c.Domain)
	def(&c.Mail.TLS, c.HTTP.TLS)
	def(&c.Mail.Storage, "rocksdb")
	defi(&c.Mail.Ports.SMTP, 25)
	defi(&c.Mail.Ports.Submissions, 465)
	defi(&c.Mail.Ports.IMAPS, 993)
	if !c.SignIn.MagicLink && !c.SignIn.Password && !c.SignIn.Username {
		c.SignIn.MagicLink, c.SignIn.Password = true, true
	}
	def(&c.Policy.Pack, "none")
	if c.Policy.Pack == "ru-152fz" {
		def(&c.Policy.Residency, "RU")
	}
	if c.Policy.Pack == "us-pii" && len(c.Policy.USStates) == 0 {
		c.Policy.USStates = []string{"CA"}
	}
	defi(&c.Ports.Management, 8080)
	defi(&c.Ports.Console, 4500)
	def(&c.Channel.Name, "stable")
	def(&c.Channel.Manifest, "https://github.com/authfly/authfly/releases/latest/download/channel.json")
	def(&c.Incus.Network, "authfly0")
	def(&c.Incus.Subnet, "10.118.42.1/24")
	def(&c.Incus.Pool, "default")
	def(&c.Incus.Image, "images:debian/13")
	def(&c.Backup.Dir, "backups")
	defi(&c.Backup.Keep, 7)
}

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)
var hostRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Validate returns every problem at once.
func (c *Config) Validate() error {
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	if c.Version != 1 {
		bad("version: only 1 is supported")
	}
	if !nameRe.MatchString(c.Name) {
		bad("name: 2-31 chars, lowercase letters, digits, dash")
	}
	oneOf := func(field, v string, list []string) {
		if !slices.Contains(list, v) {
			bad("%s: %q is not one of %s", field, v, strings.Join(list, ", "))
		}
	}
	oneOf("target", c.Target, Targets)
	oneOf("app.runtime", c.App.Runtime, Runtimes)
	oneOf("app.adapter", c.App.Adapter, Adapters)
	oneOf("policy.pack", c.Policy.Pack, Policies)
	oneOf("http.tls", c.HTTP.TLS, []string{"acme", "manual", "off"})
	oneOf("mail.tls", c.Mail.TLS, []string{"acme", "manual", "off"})
	oneOf("mail.storage", c.Mail.Storage, []string{"rocksdb"}) // other Stalwart stores: not wired yet
	if !hostRe.MatchString(c.Domain) {
		bad("domain: %q is not a hostname", c.Domain)
	}
	if !hostRe.MatchString(c.Mail.Hostname) {
		bad("mail.hostname: %q is not a hostname", c.Mail.Hostname)
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		bad("public_url: must be an absolute http(s) URL")
	} else if u.Scheme == "http" && c.HTTP.TLS != "off" {
		bad("public_url: http:// with http.tls=%s; use https://", c.HTTP.TLS)
	} // https with http.tls=off is allowed: TLS terminated by your own reverse proxy
	if c.HTTP.TLS == "manual" && (c.HTTP.CertFile == "" || c.HTTP.KeyFile == "") {
		bad("http.tls=manual needs http.cert_file and http.key_file")
	}
	if c.SignIn.Social || c.SignIn.TwoFactor || c.SignIn.WebAuthn {
		bad("sign_in: social, two_factor and webauthn are coming; leave them false")
	}
	for _, cl := range c.App.Clients {
		if cl.ID == "" || len(cl.RedirectURIs) == 0 {
			bad("app.clients: every client needs id and redirect_uris")
		}
	}
	if c.Policy.Pack == "ru-152fz" && c.Policy.Residency != "RU" {
		bad("policy.residency must be RU with ru-152fz (152-FZ Art. 18 part 5)")
	}
	if c.Policy.Pack == "ru-152fz" && c.Policy.HostCountry != "" && c.Policy.HostCountry != "RU" {
		bad("policy.host_country=%s: 152-FZ requires databases with RF citizens' data in Russia", c.Policy.HostCountry)
	}
	ports := map[int]string{}
	for n, p := range map[string]int{"http.port": c.HTTP.Port, "http.http_port": c.HTTP.HTTPPort, "mail.ports.smtp": c.Mail.Ports.SMTP,
		"mail.ports.submissions": c.Mail.Ports.Submissions, "mail.ports.imaps": c.Mail.Ports.IMAPS, "ports.management": c.Ports.Management, "ports.console": c.Ports.Console} {
		if p == 0 {
			continue
		}
		if p < 1 || p > 65535 {
			bad("%s: %d out of range", n, p)
		}
		if o, dup := ports[p]; dup {
			bad("%s and %s both use port %d", n, o, p)
		}
		ports[p] = n
	}
	return errors.Join(errs...)
}

// Load reads and validates authfly.yaml.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true) // a typo is an error, not a silently ignored setting
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.Defaults()
	c.path, _ = filepath.Abs(path)
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s:\n%w", path, err)
	}
	return c, nil
}

// Save writes authfly.yaml (no secrets ever live in it).
func (c *Config) Save(path string) error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	head := "# authfly.yaml: the single source of truth of this Authfly deployment. Edit it and run `authfly deploy` again.\n" +
		"# Secrets are not here: they live in .authfly/secrets (0600). Docs: docs/deploy.md, docs/policies.md\n"
	c.path, _ = filepath.Abs(path)
	return os.WriteFile(path, append([]byte(head), b...), 0o644)
}

// Dir is the deployment directory (next to authfly.yaml); State is its .authfly state directory.
func (c *Config) Dir() string   { return filepath.Dir(c.path) }
func (c *Config) State() string { return filepath.Join(c.Dir(), ".authfly") }
func (c *Config) Path() string  { return c.path }

// Methods is AUTHFLY_METHODS.
func (c *Config) Methods() string {
	var m []string
	if c.SignIn.MagicLink {
		m = append(m, "magic")
	}
	if c.SignIn.Password || c.SignIn.Username {
		m = append(m, "password")
	}
	return strings.Join(m, ",")
}
