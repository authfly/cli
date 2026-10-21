package deploy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Secret names. Each lives in .authfly/secrets/<name> with mode 0600 in a 0700 directory, is generated once with
// crypto/rand and is never printed (status/doctor only show "set (0600)").
var SecretNames = []string{
	"stalwart_admin_password", // Stalwart recovery admin: used by stalwart-init and the Console only
	"service_password",        // authfly-svc, the least-privilege Stalwart account Authfly uses
	"authfly_secret",          // session / token signing key
	"admin_key",               // Authfly internal admin API (Console -> Authfly)
	"console_password",        // Console sign-in (user "console")
	"console_secret",          // Console session key
	"backup_key",              // AES-256-GCM key of `authfly backup` archives: keep a copy OFF this server
}

func (c *Config) SecretDir() string { return filepath.Join(c.State(), "secrets") }

// EnsureSecrets creates missing secrets and repairs permissions; existing values are kept (idempotent).
func (c *Config) EnsureSecrets() (created []string, err error) {
	dir := c.SecretDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	for _, n := range SecretNames {
		p := filepath.Join(dir, n)
		if _, err := os.Stat(p); err == nil {
			if err := os.Chmod(p, 0o600); err != nil {
				return created, err
			}
			continue
		}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return created, err
		}
		v := hex.EncodeToString(b)
		if strings.HasSuffix(n, "password") {
			v = "Af-" + v[:40] // Stalwart rejects weak passwords; hex with a prefix passes its strength check
		}
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return created, err
		}
		_, err = f.WriteString(v)
		f.Close()
		if err != nil {
			return created, err
		}
		created = append(created, n)
	}
	return created, nil
}

// Secret reads one secret (for passing to a driver; never logged).
func (c *Config) Secret(name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(c.SecretDir(), name))
	if err != nil {
		return "", fmt.Errorf("secret %s: %w (run `authfly deploy` to generate secrets)", name, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// CheckSecretPerms reports secrets that are missing or readable by group/others.
func (c *Config) CheckSecretPerms() []string {
	var bad []string
	if st, err := os.Stat(c.SecretDir()); err != nil || st.Mode().Perm()&0o077 != 0 {
		bad = append(bad, "secrets directory is missing or not 0700")
	}
	for _, n := range SecretNames {
		st, err := os.Stat(filepath.Join(c.SecretDir(), n))
		if err != nil {
			bad = append(bad, n+": missing")
		} else if st.Mode().Perm()&0o077 != 0 {
			bad = append(bad, fmt.Sprintf("%s: mode %o, want 0600", n, st.Mode().Perm()))
		}
	}
	return bad
}

// writePrivate writes a generated file that contains secrets (env files) with 0600.
func writePrivate(path, data string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func writeFile(path, data string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(data), 0o644)
}
