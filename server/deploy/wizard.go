package deploy

import (
	"bufio"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

// Wizard asks the questions of `authfly init` on a terminal. Every answer has a secure default (Enter accepts it).
type Wizard struct {
	In  *bufio.Reader
	Out io.Writer
}

func (w Wizard) ask(q, def string) string {
	fmt.Fprintf(w.Out, "  %s [%s]: ", q, def)
	l, _ := w.In.ReadString('\n')
	if l = strings.TrimSpace(l); l == "" {
		return def
	}
	return l
}

func (w Wizard) choose(q string, opts []string, def string, notes map[string]string) string {
	fmt.Fprintf(w.Out, "\n%s\n", q)
	for i, o := range opts {
		n := ""
		if notes[o] != "" {
			n = "  — " + notes[o]
		}
		fmt.Fprintf(w.Out, "   %d) %s%s\n", i+1, o, n)
	}
	for {
		a := w.ask("choice", def)
		if i, err := strconv.Atoi(a); err == nil && i >= 1 && i <= len(opts) {
			return opts[i-1]
		}
		if slices.Contains(opts, a) {
			return a
		}
		fmt.Fprintf(w.Out, "  pick 1-%d or a name\n", len(opts))
	}
}

func (w Wizard) yes(q string, def bool) bool {
	d := "y/N"
	if def {
		d = "Y/n"
	}
	a := strings.ToLower(w.ask(q+" ("+d+")", map[bool]string{true: "y", false: "n"}[def]))
	return strings.HasPrefix(a, "y")
}

// Run fills c interactively (c already holds defaults/flags, used as the defaults of the questions).
func (w Wizard) Run(c *Config) {
	fmt.Fprintln(w.Out, "Authfly setup — 6 steps. Enter accepts the [default]. Nothing is deployed until `authfly deploy`.")
	fmt.Fprintln(w.Out, "\n[1/6] Your app")
	c.App.Runtime = w.choose("Widget runtime (the sign-in/sign-up/account UI for your app):", Runtimes, c.App.Runtime, nil)
	c.App.Adapter = w.choose("Server adapter (sign-in redirect + callback in your backend):", Adapters, c.App.Adapter, map[string]string{"node": "Node.js", "bun": "Bun", "go": "standard OIDC"})
	cb := w.ask("Your app's OIDC callback URL", firstRedirect(c))
	c.App.Clients = []Client{{ID: c.Name + "-app", Name: c.Name, RedirectURIs: []string{cb}}}

	fmt.Fprintln(w.Out, "\n[2/6] Domain and mail server (Stalwart)")
	c.Domain = w.ask("Mail domain of your users (user@domain)", c.Domain)
	c.PublicURL = w.ask("Public URL of Authfly (the OIDC issuer)", strings.Replace(c.PublicURL, "example.com", c.Domain, 1))
	c.Mail.Hostname = w.ask("Mail server hostname (MX)", strings.Replace(c.Mail.Hostname, "example.com", c.Domain, 1))
	c.HTTP.TLS = w.choose("TLS certificates:", []string{"acme", "manual", "off"}, c.HTTP.TLS, map[string]string{"acme": "Let's Encrypt, automatic (needs ports 80/443 and DNS pointing here)", "manual": "your own certificate files", "off": "only behind your own TLS proxy, or for local tests"})
	switch c.HTTP.TLS {
	case "acme":
		c.HTTP.ACMEMail = w.ask("Email for Let's Encrypt expiry notices", "admin@"+c.Domain)
	case "manual":
		c.HTTP.CertFile = w.ask("Certificate file (PEM)", c.HTTP.CertFile)
		c.HTTP.KeyFile = w.ask("Key file (PEM)", c.HTTP.KeyFile)
	}
	c.Mail.TLS = c.HTTP.TLS
	c.Mail.Storage = w.choose("Mail storage backend:", []string{"rocksdb"}, c.Mail.Storage, map[string]string{"rocksdb": "embedded, on a local volume (PostgreSQL/S3: coming)"})
	c.Mail.EncryptionAtRest = w.yes("Require encryption at rest (doctor checks the disk is LUKS-encrypted)?", c.Mail.EncryptionAtRest)
	if w.yes(fmt.Sprintf("Standard mail ports (SMTP %d, submissions %d, IMAPS %d)?", c.Mail.Ports.SMTP, c.Mail.Ports.Submissions, c.Mail.Ports.IMAPS), true) == false {
		c.Mail.Ports.SMTP, _ = strconv.Atoi(w.ask("SMTP port", fmt.Sprint(c.Mail.Ports.SMTP)))
		c.Mail.Ports.Submissions, _ = strconv.Atoi(w.ask("Submissions port", fmt.Sprint(c.Mail.Ports.Submissions)))
		c.Mail.Ports.IMAPS, _ = strconv.Atoi(w.ask("IMAPS port", fmt.Sprint(c.Mail.Ports.IMAPS)))
	}

	fmt.Fprintln(w.Out, "\n[3/6] Sign-in methods")
	c.SignIn.MagicLink = w.yes("Magic link (email a one-time sign-in link)?", c.SignIn.MagicLink)
	c.SignIn.Password = w.yes("Email + password?", c.SignIn.Password)
	c.SignIn.Username = w.yes("Username + password?", c.SignIn.Username)
	c.SignIn.RequireVerify = w.yes("Require email verification before the first sign-in?", true)
	fmt.Fprintln(w.Out, "  Social sign-in, 2FA (TOTP) and WebAuthn/passkeys: coming.")

	fmt.Fprintln(w.Out, "\n[4/6] Policy pack (templates, NOT legal advice)")
	c.Policy.Pack = w.choose("Which privacy law applies?", Policies, c.Policy.Pack, map[string]string{"gdpr": "EU users", "us-pii": "US: CCPA/CPRA (California verified; other states marked)", "ru-152fz": "Russia: data localisation in RF + Roskomnadzor notice"})
	if c.Policy.Pack != "none" {
		c.Policy.Operator = w.ask("Operator / controller legal name", c.Policy.Operator)
		c.Policy.Contact = w.ask("Privacy contact email", "privacy@"+c.Domain)
	}
	switch c.Policy.Pack {
	case "us-pii":
		c.Policy.USStates = strings.Split(strings.ToUpper(w.ask("States in scope (comma separated)", strings.Join(append([]string{"CA"}, c.Policy.USStates...)[:1], ","))), ",")
	case "ru-152fz":
		c.Policy.Residency = "RU"
		c.Policy.HostCountry = strings.ToUpper(w.ask("Country where this server physically is (ISO code; must be RU)", "RU"))
	case "gdpr":
		c.Policy.HostCountry = strings.ToUpper(w.ask("Country where this server is (ISO code)", c.Policy.HostCountry))
	}

	fmt.Fprintln(w.Out, "\n[5/6] Where to run")
	c.Target = w.choose("Target:", Targets, c.Target, map[string]string{"docker": "Docker Compose (hardened)", "incus": "Incus system containers on this host (bare metal)"})
	if c.Target == "incus" {
		c.Incus.Firewall = w.yes("Load the generated nftables firewall on this host?", true)
	}

	fmt.Fprintln(w.Out, "\n[6/6] Review")
	c.Name = w.ask("Instance name", c.Name)
}

func firstRedirect(c *Config) string {
	if len(c.App.Clients) > 0 && len(c.App.Clients[0].RedirectURIs) > 0 {
		return c.App.Clients[0].RedirectURIs[0]
	}
	return "https://" + c.Domain + "/callback"
}
