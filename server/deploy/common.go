package deploy

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// credential files derived from the secrets (all 0600 in .authfly/run): name -> content
func (c *Config) credentialFiles() (map[string]string, error) {
	get := func(n string) string { v, _ := c.Secret(n); return v }
	for _, n := range SecretNames {
		if _, err := c.Secret(n); err != nil {
			return nil, err
		}
	}
	return map[string]string{
		"stalwart_admin":   "admin:" + get("stalwart_admin_password"),
		"stalwart_service": "authfly-svc@" + c.Domain + ":" + get("service_password"),
		"service_password": get("service_password"),
		"authfly_secret":   get("authfly_secret"),
		"admin_key":        get("admin_key"),
		"console_admin":    "console:" + get("console_password"),
		"console_secret":   get("console_secret"),
		"stalwart.env":     "STALWART_RECOVERY_ADMIN=admin:" + get("stalwart_admin_password") + "\n",
	}, nil
}

func (c *Config) writeCredentialFiles() error {
	files, err := c.credentialFiles()
	if err != nil {
		return err
	}
	for n, v := range files {
		if err := writePrivate(filepath.Join(c.State(), "run", n), v); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) clientsJSON() string {
	b, _ := json.Marshal(c.App.Clients)
	if len(c.App.Clients) == 0 {
		return "[]"
	}
	return string(b)
}

// env of the three Authfly processes. secretDir is where the credential files are mounted inside the instance.
func (c *Config) authflyEnv(p Pack, stalwartURL, smtpAddr, secretDir, dataDir string) map[string]string {
	e := map[string]string{
		"AUTHFLY_DOMAIN": c.Domain, "AUTHFLY_PUBLIC_URL": c.PublicURL, "STALWART_URL": stalwartURL,
		"STALWART_ADMIN_FILE": secretDir + "/stalwart_service", "AUTHFLY_SECRET_FILE": secretDir + "/authfly_secret",
		"AUTHFLY_CLIENTS": c.clientsJSON(), "AUTHFLY_PRODUCT": "Authfly", "SMTP_ADDR": smtpAddr, "SMTP_FROM": "noreply@" + c.Domain,
		"AUTHFLY_AUDIT_RETENTION": fmt.Sprintf("%dh", int(p.AuditRetention.Hours())), "AUTHFLY_ADMIN_ADDR": ":4001",
		"AUTHFLY_ADMIN_KEY_FILE": secretDir + "/admin_key", "AUTHFLY_STORE": dataDir + "/store.json", "AUTHFLY_METHODS": c.Methods(),
		"AUTHFLY_REQUIRE_VERIFIED": fmt.Sprint(c.SignIn.RequireVerify), "AUTHFLY_POLICY": p.ID, "AUTHFLY_LEGAL_DIR": dataDir + "/legal",
		"AUTHFLY_TLS_MODE": c.HTTP.TLS, "AUTHFLY_ADDR": ":4000",
	}
	if p.TermsLabel != "" {
		e["AUTHFLY_TERMS_LABEL"] = p.TermsLabel
	}
	if len(p.ExtraConsents) > 0 {
		e["AUTHFLY_EXTRA_CONSENTS"] = strings.Join(p.ExtraConsents, ",")
	}
	if c.HTTP.TLS != "off" {
		e["AUTHFLY_ADDR"] = ":4443"
		e["AUTHFLY_HTTP_ADDR"] = ":4080"
		e["AUTHFLY_TLS_CACHE"] = dataDir + "/acme"
		e["AUTHFLY_TLS_HOSTS"] = hostOf(c.PublicURL)
		e["AUTHFLY_ACME_EMAIL"] = c.HTTP.ACMEMail
		if c.HTTP.TLS == "manual" {
			e["AUTHFLY_TLS_CERT"], e["AUTHFLY_TLS_KEY"] = secretDir+"/tls.crt", secretDir+"/tls.key"
		}
	}
	return e
}

func (c *Config) initEnv(stalwartURL, secretDir string) map[string]string {
	return map[string]string{"STALWART_URL": stalwartURL, "STALWART_ADMIN_FILE": secretDir + "/stalwart_admin", "AUTHFLY_DOMAIN": c.Domain,
		"AUTHFLY_PUBLIC_URL": c.PublicURL, "AUTHFLY_SERVICE_PASSWORD_FILE": secretDir + "/service_password", "AUTHFLY_CLIENTS": c.clientsJSON()}
}

func (c *Config) consoleEnv(stalwartURL, authflyAdminURL, secretDir, dataDir string) map[string]string {
	return map[string]string{"CONSOLE_ADDR": ":4500", "STALWART_URL": stalwartURL, "STALWART_ADMIN_FILE": secretDir + "/stalwart_admin",
		"AUTHFLY_ADMIN_URL": authflyAdminURL, "AUTHFLY_ADMIN_KEY_FILE": secretDir + "/admin_key", "AUTHFLY_DOMAIN": c.Domain,
		"AUTHFLY_PUBLIC_URL": c.PublicURL, "CONSOLE_ADMIN_FILE": secretDir + "/console_admin", "CONSOLE_SECRET_FILE": secretDir + "/console_secret", "CONSOLE_DATA": dataDir}
}

func hostOf(u string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexAny(h, ":/"); i >= 0 {
		h = h[:i]
	}
	return h
}

func sortedKeys(m map[string]string) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

// Log is the CLI's step logger (never receives secret values).
var Log = func(f string, a ...any) { fmt.Printf("  "+f+"\n", a...) }

// run executes a command; output is returned for errors (commands never carry secrets on argv).
func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// waitHTTP polls a URL until it answers (any status < 500).
func waitHTTP(url string, d time.Duration) error {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if out, err := exec.Command("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "3", url).Output(); err == nil {
			if s := string(out); s != "000" && s < "500" {
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("%s did not come up within %s", url, d)
}
