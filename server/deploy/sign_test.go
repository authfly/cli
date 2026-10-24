package deploy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

const testChannel = `{"channel":"stable","releases":[{"version":"0.4.0","files":{},"images":{}},{"version":"0.4.1","files":{},"images":{}}]}`

// testSigner signs like `ssh-keygen -Y sign`: plain ssh-ed25519, or a software stand-in for a FIDO2 sk-ed25519 key
// that follows the authenticator's rules (PROTOCOL.u2f): ed25519 over
// sha256(application) || flags || counter (uint32 BE) || sha256(SSHSIG signed data).
type testSigner struct {
	priv  ed25519.PrivateKey
	app   string // "" = plain ssh-ed25519
	pub   ssh.PublicKey
	flags byte
}

func newSigner(t *testing.T, app string) *testSigner {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return withApp(t, priv, pub, app)
}

func withApp(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, app string) *testSigner {
	s := &testSigner{priv: priv, app: app, flags: skFlagUP}
	var err error
	if app == "" {
		s.pub, err = ssh.NewPublicKey(pub)
	} else {
		s.pub, err = ssh.ParsePublicKey(ssh.Marshal(struct{ Type, PubKey, App string }{ssh.KeyAlgoSKED25519, string(pub), app}))
	}
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *testSigner) authorized() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.pub))) + " test key"
}

// sign returns an armored SSHSIG over data; signApp/namespace/hash can be overridden to build bad signatures.
func (s *testSigner) sign(data []byte, namespace, hash, signApp string) []byte {
	var digest []byte
	if hash == "sha512" {
		h := sha512.Sum512(data)
		digest = h[:]
	} else {
		h := sha256.Sum256(data)
		digest = h[:]
	}
	msg := signedData(namespace, "", hash, digest)
	var sig ssh.Signature
	if s.app == "" {
		sig = ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: ed25519.Sign(s.priv, msg)}
	} else {
		appH, msgH := sha256.Sum256([]byte(signApp)), sha256.Sum256(msg)
		counter := []byte{0, 0, 0, 42}
		blob := append(append(append(appH[:], s.flags), counter...), msgH[:]...)
		sig = ssh.Signature{Format: ssh.KeyAlgoSKED25519, Blob: ed25519.Sign(s.priv, blob), Rest: append([]byte{s.flags}, counter...)}
	}
	raw := append([]byte(sigMagic), 0, 0, 0, 1)
	raw = append(raw, ssh.Marshal(struct {
		PublicKey                    []byte
		Namespace, Reserved, HashAlg string
		Signature                    []byte
	}{s.pub.Marshal(), namespace, "", hash, ssh.Marshal(sig)})...)
	b64 := base64.StdEncoding.EncodeToString(raw)
	var out strings.Builder
	out.WriteString(armorBegin + "\n")
	for len(b64) > 70 {
		out.WriteString(b64[:70] + "\n")
		b64 = b64[70:]
	}
	out.WriteString(b64 + "\n" + armorEnd + "\n")
	return []byte(out.String())
}

func (s *testSigner) good(data []byte) []byte { return s.sign(data, SigNamespace, "sha512", s.app) }

func ring(t *testing.T, lines ...string) []TrustedKey {
	r, err := Keyring(lines)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func withTrusted(t *testing.T, lines ...string) {
	old := trustedKeys
	trustedKeys = lines
	t.Cleanup(func() { trustedKeys = old })
}

func wantSigErr(t *testing.T, name string, err error, sub string) {
	t.Helper()
	if !errors.Is(err, ErrChannelSignature) || !strings.Contains(err.Error(), sub) {
		t.Errorf("%s: want a channel signature error containing %q, got %v", name, sub, err)
	}
}

func TestBuiltInKeyring(t *testing.T) {
	r := ring(t, TrustedKeys...)
	if len(r) != 1 || r[0].Fingerprint() != "SHA256:dhhWLt7kJTEad+0i8nBdu8MHeA5SgPDYQNXQmL8oPGc" ||
		r[0].Key.Type() != ssh.KeyAlgoSKED25519 || skApplication(r[0].Key) != "ssh:authfly-release" {
		t.Fatalf("built-in release key: %+v", r)
	}
	if _, err := Keyring([]string{"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7 x"}); err == nil {
		t.Error("an rsa key must be refused")
	}
	if _, err := Keyring([]string{newSigner(t, "authfly-release").authorized()}); err == nil {
		t.Error("an sk key whose application does not start with ssh: must be refused")
	}
}

func TestVerifySK(t *testing.T) {
	data := []byte(testChannel)
	yk := newSigner(t, "ssh:authfly-release")
	trusted := ring(t, yk.authorized())

	if who, err := VerifyChannel(data, yk.good(data), trusted); err != nil || !strings.Contains(who, yk.pub.Type()) || !strings.Contains(who, "touch, counter 42") {
		t.Fatalf("valid sk signature: %q %v", who, err)
	}
	// tampered manifest
	bad := []byte(strings.Replace(testChannel, "0.4.1", "0.4.2", 1))
	_, err := VerifyChannel(bad, yk.good(data), trusted)
	wantSigErr(t, "tampered", err, "modified")
	// no user presence (UP flag cleared: the key was not touched)
	noUP := *yk
	noUP.flags = 0
	_, err = VerifyChannel(data, noUP.good(data), trusted)
	wantSigErr(t, "no UP", err, "user presence")
	// UV (PIN) on top of UP is fine
	uv := *yk
	uv.flags = skFlagUP | skFlagUV
	if who, err := VerifyChannel(data, uv.good(data), trusted); err != nil || !strings.Contains(who, "touch+PIN") {
		t.Errorf("UP+UV: %q %v", who, err)
	}
	// other namespace (a signature made for git or for file signing must not be a channel signature)
	_, err = VerifyChannel(data, yk.sign(data, "git", "sha512", yk.app), trusted)
	wantSigErr(t, "namespace", err, `namespace "git"`)
	// other hash
	_, err = VerifyChannel(data, yk.sign(data, SigNamespace, "sha256", yk.app), trusted)
	wantSigErr(t, "hash", err, "sha512")
	// other application: the authenticator signed for ssh:other while the blob names the trusted key
	_, err = VerifyChannel(data, yk.sign(data, SigNamespace, "sha512", "ssh:other"), trusted)
	wantSigErr(t, "other app (signed data)", err, "modified")
	// other application: same ed25519 key registered under another application is a different (untrusted) key
	other := withApp(t, yk.priv, yk.priv.Public().(ed25519.PublicKey), "ssh:other")
	_, err = VerifyChannel(data, other.good(data), trusted)
	wantSigErr(t, "other app (key)", err, "unknown key")
	// unknown key
	stranger := newSigner(t, "ssh:authfly-release")
	_, err = VerifyChannel(data, stranger.good(data), trusted)
	wantSigErr(t, "unknown key", err, "unknown key "+ssh.FingerprintSHA256(stranger.pub))
	// garbage
	_, err = VerifyChannel(data, []byte("not a signature"), trusted)
	wantSigErr(t, "garbage", err, "BEGIN SSH SIGNATURE")
}

func TestVerifyRotation(t *testing.T) {
	data := []byte(testChannel)
	old, spare := newSigner(t, "ssh:authfly-release"), newSigner(t, "ssh:authfly-release-2")
	both := append(old.good(data), spare.good(data)...) // two ssh-keygen outputs concatenated
	if _, err := VerifyChannel(data, both, ring(t, old.authorized())); err != nil {
		t.Errorf("rotation, CLI with the old key only: %v", err)
	}
	if _, err := VerifyChannel(data, both, ring(t, spare.authorized())); err != nil {
		t.Errorf("rotation, CLI with the new key only: %v", err)
	}
	if who, err := VerifyChannel(data, both, ring(t, old.authorized(), spare.authorized())); err != nil || strings.Count(who, "SHA256:") != 2 {
		t.Errorf("rotation, both trusted: %q %v", who, err)
	}
	// a trusted key whose block does not verify fails the channel even if another trusted key verifies
	noUP := *old
	noUP.flags = 0
	mixed := append(noUP.good(data), spare.good(data)...)
	_, err := VerifyChannel(data, mixed, ring(t, old.authorized(), spare.authorized()))
	wantSigErr(t, "bad + good", err, "user presence")
	// a plain ssh-ed25519 spare key works too
	ed := newSigner(t, "")
	if _, err := VerifyChannel(data, ed.good(data), ring(t, ed.authorized())); err != nil {
		t.Errorf("ssh-ed25519: %v", err)
	}
}

// Cross-checks with OpenSSH: ssh-keygen -Y sign output verifies here, and our sk fixture verifies in ssh-keygen.
func TestOpenSSHInterop(t *testing.T) {
	kg, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed")
	}
	d := t.TempDir()
	file := filepath.Join(d, "channel.json")
	os.WriteFile(file, []byte(testChannel), 0o644)
	key := filepath.Join(d, "id")
	if out, err := exec.Command(kg, "-q", "-t", "ed25519", "-N", "", "-C", "interop", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v %s", err, out)
	}
	pub, _ := os.ReadFile(key + ".pub")
	sign := func(ns string) []byte {
		os.Remove(file + ".sig")
		if out, err := exec.Command(kg, "-Y", "sign", "-n", ns, "-f", key, file).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen -Y sign: %v %s", err, out)
		}
		b, _ := os.ReadFile(file + ".sig")
		return b
	}
	tr := ring(t, strings.TrimSpace(string(pub)))
	if _, err := VerifyChannel([]byte(testChannel), sign(SigNamespace), tr); err != nil {
		t.Errorf("ssh-keygen signature rejected: %v", err)
	}
	_, err = VerifyChannel([]byte(testChannel), sign("file"), tr)
	wantSigErr(t, "ssh-keygen, namespace file", err, "namespace")

	verify := func(sig []byte, signer string) error {
		allowed := filepath.Join(d, "allowed_signers")
		os.WriteFile(allowed, []byte("authfly-release namespaces=\""+SigNamespace+"\" "+signer+"\n"), 0o644)
		sf := filepath.Join(d, "x.sig")
		os.WriteFile(sf, sig, 0o644)
		cmd := exec.Command(kg, "-Y", "verify", "-f", allowed, "-I", "authfly-release", "-n", SigNamespace, "-s", sf)
		cmd.Stdin = bytes.NewReader([]byte(testChannel))
		out, err := cmd.CombinedOutput()
		if err != nil {
			return errors.New(string(out))
		}
		return nil
	}
	yk := newSigner(t, "ssh:authfly-release")
	if err := verify(yk.good([]byte(testChannel)), yk.authorized()); err != nil {
		t.Errorf("ssh-keygen rejects our sk fixture: %v", err)
	}
	noUP := *yk
	noUP.flags = 0
	// ssh-keygen -Y verify checks the signature math only and does not require user presence for SSHSIG (sshd does
	// for logins; ssh-keygen.c sig_verify only logs the flags). The CLI is stricter and refuses it (TestVerifySK).
	if err := verify(noUP.good([]byte(testChannel)), yk.authorized()); err != nil {
		t.Errorf("ssh-keygen rejects the no-UP fixture (math should still verify): %v", err)
	}
	if _, err := VerifyChannel([]byte(testChannel), noUP.good([]byte(testChannel)), ring(t, yk.authorized())); err == nil {
		t.Error("the CLI accepted an sk signature without user presence")
	}
	ed := newSigner(t, "")
	if err := verify(ed.good([]byte(testChannel)), ed.authorized()); err != nil {
		t.Errorf("ssh-keygen rejects our ed25519 fixture: %v", err)
	}
}

func channelDir(t *testing.T, s *testSigner) string {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "channel.json"), []byte(testChannel), 0o644)
	if s != nil {
		os.WriteFile(filepath.Join(d, "channel.json.sig"), s.good([]byte(testChannel)), 0o644)
	}
	return d
}

func TestLoadManifestSignature(t *testing.T) {
	yk, stranger := newSigner(t, "ssh:authfly-release"), newSigner(t, "ssh:authfly-release")
	withTrusted(t, yk.authorized())
	c := testConfig(t, "gdpr", "docker")

	c.Channel.Manifest = filepath.Join(channelDir(t, yk), "channel.json")
	if m, err := c.LoadManifest(); err != nil || !strings.Contains(m.SignedBy, ssh.FingerprintSHA256(yk.pub)) || len(m.Releases) != 2 {
		t.Fatalf("signed file channel: %+v %v", m, err)
	}
	c.Channel.Manifest = "file://" + filepath.Join(channelDir(t, nil), "channel.json")
	_, err := c.LoadManifest()
	wantSigErr(t, "unsigned file channel without dev mode", err, "allow_unsigned")
	c.Channel.AllowUnsigned = true
	if m, err := c.LoadManifest(); err != nil || m.SignedBy != "" {
		t.Fatalf("dev mode: %+v %v", m, err)
	}
	d := channelDir(t, yk)
	os.WriteFile(filepath.Join(d, "channel.json"), []byte(strings.Replace(testChannel, "0.4.1", "0.4.9", 1)), 0o644)
	c.Channel.Manifest = filepath.Join(d, "channel.json")
	_, err = c.LoadManifest()
	wantSigErr(t, "dev mode + tampered", err, "modified")
	c.Channel.Manifest = filepath.Join(channelDir(t, stranger), "channel.json")
	_, err = c.LoadManifest()
	wantSigErr(t, "dev mode + unknown key", err, "unknown key")
}

func TestHTTPSChannelMustBeSigned(t *testing.T) {
	yk := newSigner(t, "ssh:authfly-release")
	withTrusted(t, yk.authorized())
	sig := yk.good([]byte(testChannel))
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
	if _, err := c.LoadManifest(); err != nil {
		t.Fatalf("signed https channel: %v", err)
	}
	signed = false
	_, err := c.LoadManifest()
	wantSigErr(t, "unsigned https", err, "unsigned")
	c.Channel.AllowUnsigned = true
	_, err = c.LoadManifest()
	wantSigErr(t, "unsigned https + allow_unsigned", err, "unsigned")
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "allow_unsigned") {
		t.Fatalf("validate https + allow_unsigned: %v", err)
	}
}
