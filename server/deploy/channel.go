package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Channel manifest (channel.json). Every artifact is pinned by sha256 (files) or registry digest (images);
// deploy/upgrade refuse anything that does not match. The manifest itself is signed: LoadManifest verifies the
// detached channel.json.sig (Ed25519, sign.go) against the keys built into the CLI before trusting any digest in it.
type Artifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

type Release struct {
	Version string              `json:"version"`
	Files   map[string]Artifact `json:"files"`  // <authfly|console|stalwart>-linux-<amd64|arm64> (stalwart: upstream tar.gz); see ArchFile
	Images  map[string]string   `json:"images"` // authfly, console, stalwart -> ref@sha256:<multi-arch index digest>, or ref@<image id> for local builds
	Notes   string              `json:"notes,omitempty"`
}

type Manifest struct {
	Channel  string    `json:"channel"`
	Releases []Release `json:"releases"` // newest last
	SignedBy string    `json:"-"`        // key id that signed it; "" = unsigned dev channel (channel.allow_unsigned)
}

// ArchFile is the files key of a binary for this host's architecture (Incus runs the binaries on the host's arch).
func ArchFile(base string) string { return base + "-linux-" + runtime.GOARCH }

// signatureRequired: https channels must always be signed; channel.allow_unsigned only covers file paths, file:// and
// plain http:// dev servers (tools/release.sh, e2e).
func (c *Config) signatureRequired() bool {
	return !c.Channel.AllowUnsigned || strings.HasPrefix(c.Channel.Manifest, "https://")
}

var httpClient = &http.Client{Timeout: 60 * time.Second}

func fetch(src string) ([]byte, error) {
	if strings.HasPrefix(src, "https://") || strings.HasPrefix(src, "http://") {
		r, err := httpClient.Get(src)
		if err != nil {
			return nil, err
		}
		defer r.Body.Close()
		if r.StatusCode != 200 {
			return nil, fmt.Errorf("GET %s: %s", src, r.Status)
		}
		return io.ReadAll(io.LimitReader(r.Body, 512<<20))
	}
	return os.ReadFile(strings.TrimPrefix(src, "file://"))
}

// LoadManifest reads the channel manifest named in authfly.yaml (relative paths are relative to authfly.yaml).
func (c *Config) LoadManifest() (*Manifest, error) {
	src := c.Channel.Manifest
	if !strings.Contains(src, "://") && !filepath.IsAbs(src) {
		src = filepath.Join(c.Dir(), src)
	}
	b, err := fetch(src)
	if err != nil {
		return nil, fmt.Errorf("channel manifest: %w", err)
	}
	m := &Manifest{}
	// The signature is checked on the raw bytes before anything in them is parsed or trusted.
	if sig, serr := fetch(src + ".sig"); serr == nil {
		ring, err := Keyring(trustedKeys)
		if err != nil {
			return nil, err
		}
		if m.SignedBy, err = VerifyChannel(b, sig, ring); err != nil {
			return nil, fmt.Errorf("channel %s: %w", src, err)
		}
	} else if c.signatureRequired() {
		return nil, fmt.Errorf("channel %s: %w: no channel.json.sig (%v): refusing an unsigned channel. Official channels are signed; "+
			"for a local or dev channel (file or http://) set channel.allow_unsigned: true (authfly init --allow-unsigned-channel)", src, ErrChannelSignature, serr)
	}
	if err := json.Unmarshal(b, m); err != nil {
		return nil, fmt.Errorf("channel manifest: %w", err)
	}
	if len(m.Releases) == 0 {
		return nil, fmt.Errorf("channel manifest: no releases")
	}
	return m, nil
}

// Find returns the release with version v ("" = newest).
func (m *Manifest) Find(v string) (*Release, error) {
	if v == "" {
		return &m.Releases[len(m.Releases)-1], nil
	}
	for i := range m.Releases {
		if m.Releases[i].Version == v {
			return &m.Releases[i], nil
		}
	}
	return nil, fmt.Errorf("release %s is not in channel %s", v, m.Channel)
}

func sha256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// FetchVerified downloads (or copies) an artifact into .authfly/cache and verifies its sha256; a mismatch deletes it.
func (c *Config) FetchVerified(name string, a Artifact) (string, error) {
	dir := filepath.Join(c.State(), "cache")
	os.MkdirAll(dir, 0o755)
	dst := filepath.Join(dir, a.SHA256[:16]+"-"+name)
	if sum, err := sha256File(dst); err == nil && sum == a.SHA256 {
		return dst, nil
	}
	b, err := fetch(a.URL)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != a.SHA256 {
		return "", fmt.Errorf("%s: checksum mismatch (got %s, channel says %s): refusing to install", name, got, a.SHA256)
	}
	if err := os.WriteFile(dst, b, 0o755); err != nil {
		return "", err
	}
	return dst, nil
}

// DeployState records what is running (status, upgrade, rollback).
type DeployState struct {
	Current   string    `json:"current"`
	Previous  string    `json:"previous,omitempty"`
	Snapshot  string    `json:"snapshot,omitempty"` // pre-upgrade snapshot / backup name for rollback
	UpdatedAt time.Time `json:"updated_at"`
	ConfigSHA string    `json:"config_sha"`
}

func (c *Config) LoadState() DeployState {
	var s DeployState
	b, _ := os.ReadFile(filepath.Join(c.State(), "state.json"))
	json.Unmarshal(b, &s)
	return s
}

func (c *Config) SaveState(s DeployState) error {
	s.UpdatedAt = time.Now().UTC()
	s.ConfigSHA, _ = sha256File(c.Path())
	b, _ := json.MarshalIndent(s, "", "  ")
	return writeFile(filepath.Join(c.State(), "state.json"), string(b)+"\n")
}
