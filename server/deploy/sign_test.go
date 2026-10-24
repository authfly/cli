package deploy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testChannel = `{"channel":"stable","releases":[{"version":"0.4.0","files":{},"images":{}},{"version":"0.4.1","files":{},"images":{}}]}`

func newKey(t *testing.T) (ed25519.PrivateKey, string, string) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, KeyID(pub), base64.StdEncoding.EncodeToString(pub)
}

// withTrusted makes LoadManifest trust exactly the given keys for one test.
func withTrusted(t *testing.T, m map[string]string) {
	old := trustedKeys
	trustedKeys = m
	t.Cleanup(func() { trustedKeys = old })
}

func ring(t *testing.T, m map[string]string) map[string]ed25519.PublicKey {
	r, err := Keyring(m)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestBuiltInKeyring(t *testing.T) {
	r := ring(t, TrustedKeys) // ids match their keys
	if len(r) == 0 {
		t.Fatal("no trusted release key built in")
	}
	if _, err := Keyring(map[string]string{"0000000000000000": base64.StdEncoding.EncodeToString(make([]byte, 32))}); err == nil {
		t.Fatal("a key id that does not match its key must be refused")
	}
}

func TestVerifyChannel(t *testing.T) {
	k1, id1, pub1 := newKey(t)
	k2, id2, pub2 := newKey(t)
	data := []byte(testChannel)
	trusted := ring(t, map[string]string{id1: pub1})

	sig, _ := SignChannel(data, k1)
	if id, err := VerifyChannel(data, sig, trusted); err != nil || id != id1 {
		t.Fatalf("valid signature: %q %v", id, err)
	}
	// tampered manifest (one digit of a version, i.e. any byte of the file)
	bad := []byte(strings.Replace(testChannel, "0.4.1", "0.4.2", 1))
	if _, err := VerifyChannel(bad, sig, trusted); !errors.Is(err, ErrChannelSignature) || !strings.Contains(err.Error(), "modified") {
		t.Fatalf("tampered: %v", err)
	}
	// unknown key id
	sig2, _ := SignChannel(data, k2)
	if _, err := VerifyChannel(data, sig2, trusted); !errors.Is(err, ErrChannelSignature) || !strings.Contains(err.Error(), "unknown key id "+id2) {
		t.Fatalf("unknown key: %v", err)
	}
	// rotation: signed by old (trusted) + new (not yet trusted) key -> ok with either keyring
	both, _ := SignChannel(data, k1, k2)
	if id, err := VerifyChannel(data, both, trusted); err != nil || id != id1 {
		t.Fatalf("rotation, old CLI: %q %v", id, err)
	}
	if id, err := VerifyChannel(data, both, ring(t, map[string]string{id2: pub2})); err != nil || id != id2 {
		t.Fatalf("rotation, new CLI: %q %v", id, err)
	}
	// a bad signature by a trusted key is refused even if another trusted key verifies
	forged := strings.Replace(string(both), `"sig": "`, `"sig": "AA`, 1)
	if _, err := VerifyChannel(data, []byte(forged), ring(t, map[string]string{id1: pub1, id2: pub2})); !errors.Is(err, ErrChannelSignature) {
		t.Fatalf("forged entry accepted: %v", err)
	}
	if _, err := VerifyChannel(data, []byte(`{"signatures":[]}`), trusted); !errors.Is(err, ErrChannelSignature) {
		t.Fatalf("garbage .sig: %v", err)
	}
}

func channelDir(t *testing.T, sign ed25519.PrivateKey) string {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "channel.json"), []byte(testChannel), 0o644)
	if sign != nil {
		sig, _ := SignChannel([]byte(testChannel), sign)
		os.WriteFile(filepath.Join(d, "channel.json.sig"), sig, 0o644)
	}
	return d
}

func TestLoadManifestSignature(t *testing.T) {
	k1, id1, pub1 := newKey(t)
	k2, _, _ := newKey(t)
	withTrusted(t, map[string]string{id1: pub1})
	c := testConfig(t, "gdpr", "docker")

	// signed file channel
	c.Channel.Manifest = filepath.Join(channelDir(t, k1), "channel.json")
	if m, err := c.LoadManifest(); err != nil || m.SignedBy != id1 || len(m.Releases) != 2 {
		t.Fatalf("signed file channel: %+v %v", m, err)
	}
	// unsigned file channel: refused by default, accepted in dev mode
	c.Channel.Manifest = "file://" + filepath.Join(channelDir(t, nil), "channel.json")
	if _, err := c.LoadManifest(); !errors.Is(err, ErrChannelSignature) || !strings.Contains(err.Error(), "allow_unsigned") {
		t.Fatalf("unsigned file channel without dev mode: %v", err)
	}
	c.Channel.AllowUnsigned = true
	if m, err := c.LoadManifest(); err != nil || m.SignedBy != "" {
		t.Fatalf("dev mode: %+v %v", m, err)
	}
	// dev mode never accepts a wrong signature
	d := channelDir(t, k1)
	os.WriteFile(filepath.Join(d, "channel.json"), []byte(strings.Replace(testChannel, "0.4.1", "0.4.9", 1)), 0o644)
	c.Channel.Manifest = filepath.Join(d, "channel.json")
	if _, err := c.LoadManifest(); !errors.Is(err, ErrChannelSignature) {
		t.Fatalf("dev mode + tampered: %v", err)
	}
	// dev mode + signed by an unknown key: refused too
	c.Channel.Manifest = filepath.Join(channelDir(t, k2), "channel.json")
	if _, err := c.LoadManifest(); !errors.Is(err, ErrChannelSignature) {
		t.Fatalf("dev mode + unknown key: %v", err)
	}
}

func TestHTTPSChannelMustBeSigned(t *testing.T) {
	k1, id1, pub1 := newKey(t)
	withTrusted(t, map[string]string{id1: pub1})
	sig, _ := SignChannel([]byte(testChannel), k1)
	signed := true
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/channel.json":
			w.Write([]byte(testChannel))
		case r.URL.Path == "/channel.json.sig" && signed:
			w.Write(sig)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	old := httpClient
	httpClient = ts.Client()
	defer func() { httpClient = old }()
	c := testConfig(t, "gdpr", "docker")
	c.Channel.Manifest = ts.URL + "/channel.json"
	if m, err := c.LoadManifest(); err != nil || m.SignedBy != id1 {
		t.Fatalf("signed https channel: %v", err)
	}
	signed = false
	if _, err := c.LoadManifest(); !errors.Is(err, ErrChannelSignature) || !strings.Contains(err.Error(), "unsigned") {
		t.Fatalf("unsigned https channel: %v", err)
	}
	c.Channel.AllowUnsigned = true // not honored for https, and the config is invalid
	if _, err := c.LoadManifest(); !errors.Is(err, ErrChannelSignature) {
		t.Fatalf("unsigned https channel with allow_unsigned: %v", err)
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "allow_unsigned") {
		t.Fatalf("validate https + allow_unsigned: %v", err)
	}
}
