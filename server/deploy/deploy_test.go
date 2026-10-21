package deploy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testConfig(t *testing.T, pack, target string) *Config {
	dir := t.TempDir()
	c := &Config{Target: target}
	c.Policy.Pack = pack
	c.Policy.HostCountry = map[string]string{"ru-152fz": "RU"}[pack]
	c.Defaults()
	if err := c.Save(filepath.Join(dir, "authfly.yaml")); err != nil {
		t.Fatal(err)
	}
	l, err := Load(filepath.Join(dir, "authfly.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestConfigRoundTripAndValidation(t *testing.T) {
	c := testConfig(t, "gdpr", "docker")
	if c.HTTP.Port != 443 || c.HTTP.TLS != "acme" || c.Ports.Management != 8080 {
		t.Fatalf("defaults: %+v", c.HTTP)
	}
	bad := *c
	bad.Target, bad.App.Runtime = "k8s", "angular"
	bad.Policy.Pack, bad.Policy.Residency = "ru-152fz", "DE"
	bad.SignIn.WebAuthn = true
	err := bad.Validate()
	for _, want := range []string{"target", "app.runtime", "residency", "coming"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q in %v", want, err)
		}
	}
	os.WriteFile(c.Path(), []byte("version: 1\ntarget: docker\ntypo_field: 1\n"), 0o644)
	if _, err := Load(c.Path()); err == nil || !strings.Contains(err.Error(), "typo_field") {
		t.Errorf("unknown field accepted: %v", err)
	}
}

func TestSecretsAre0600AndStable(t *testing.T) {
	c := testConfig(t, "none", "docker")
	created, err := c.EnsureSecrets()
	if err != nil || len(created) != len(SecretNames) {
		t.Fatal(created, err)
	}
	v1, _ := c.Secret("authfly_secret")
	again, _ := c.EnsureSecrets()
	v2, _ := c.Secret("authfly_secret")
	if len(again) != 0 || v1 != v2 || len(v1) != 64 {
		t.Fatal("secrets must be generated once")
	}
	if bad := c.CheckSecretPerms(); len(bad) != 0 {
		t.Fatal(bad)
	}
	os.Chmod(filepath.Join(c.SecretDir(), "admin_key"), 0o644)
	if bad := c.CheckSecretPerms(); len(bad) != 1 {
		t.Fatal("0644 not reported", bad)
	}
	c.EnsureSecrets()
	if bad := c.CheckSecretPerms(); len(bad) != 0 {
		t.Fatal("perms not repaired", bad)
	}
}

func TestBackupEncryption(t *testing.T) {
	c := testConfig(t, "none", "docker")
	c.EnsureSecrets()
	a, _ := c.backupAEAD()
	data := bytes.Repeat([]byte("personal data "), 300000) // > 4 chunks
	var enc bytes.Buffer
	if err := encryptTo(&enc, a, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc.Bytes(), []byte("personal data")) {
		t.Fatal("plaintext in archive")
	}
	got, err := decryptFrom(bytes.NewReader(enc.Bytes()), a)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("round trip", err)
	}
	b := enc.Bytes()
	if _, err := decryptFrom(bytes.NewReader(b[:len(b)-100]), a); err == nil {
		t.Fatal("truncation not detected")
	}
	if _, err := decryptFrom(bytes.NewReader(b[:len(b)-(len(b)-20)%(1<<20+20)]), a); err == nil {
		t.Fatal("chunk truncation not detected")
	}
	b2 := append([]byte{}, b...)
	b2[100] ^= 1
	if _, err := decryptFrom(bytes.NewReader(b2), a); err == nil {
		t.Fatal("tampering not detected")
	}
	var empty bytes.Buffer
	encryptTo(&empty, a, bytes.NewReader(nil))
	if got, err := decryptFrom(&empty, a); err != nil || len(got) != 0 {
		t.Fatal("empty", err)
	}
}

func TestPacks(t *testing.T) {
	ru := PackFor(testConfig(t, "ru-152fz", "incus"))
	if ru.Residency != "RU" || len(ru.ExtraConsents) != 1 || ru.Documents["pd-consent"] == "" || !strings.Contains(ru.Documents["pd-consent"], "НЕ") && !strings.Contains(ru.Documents["pd-consent"], "NOT LEGAL ADVICE") {
		t.Fatalf("ru pack: %+v", ru.ExtraConsents)
	}
	g := PackFor(testConfig(t, "gdpr", "docker"))
	if !strings.Contains(g.Documents["privacy"], "Art. 12(3)") || g.Documents["records-of-processing"] == "" {
		t.Fatal("gdpr docs")
	}
	us := PackFor(testConfig(t, "us-pii", "docker"))
	if !strings.Contains(us.Documents["privacy"], "§1798.130(a)(2)") || !strings.Contains(strings.Join(us.Reminders, " "), "UNVERIFIED") {
		t.Fatal("us docs")
	}
	for _, p := range []Pack{ru, g, us} {
		for n, d := range p.Documents {
			if !strings.HasPrefix(d, notLegalAdvice) {
				t.Errorf("%s/%s lacks the not-legal-advice header", p.ID, n)
			}
		}
	}
}

func TestEnvNeverCarriesSecrets(t *testing.T) {
	c := testConfig(t, "gdpr", "docker")
	c.EnsureSecrets()
	env := c.authflyEnv(PackFor(c), "http://s:8080", "s:25", "/run/secrets", "/data")
	for _, n := range SecretNames {
		v, _ := c.Secret(n)
		for k, e := range env {
			if strings.Contains(e, v) {
				t.Fatalf("secret %s in env %s", n, k)
			}
		}
	}
	if env["AUTHFLY_SECRET_FILE"] == "" || env["AUTHFLY_AUDIT_RETENTION"] != "8760h" {
		t.Fatal(env)
	}
}

func TestNFT(t *testing.T) {
	c := testConfig(t, "ru-152fz", "incus")
	n := c.NFTables()
	for _, want := range []string{"policy drop", "tcp dport 22", "tcp dport { 8080, 4500 } drop", `iifname "authfly0"`} {
		if !strings.Contains(n, want) {
			t.Errorf("nft lacks %q", want)
		}
	}
}
