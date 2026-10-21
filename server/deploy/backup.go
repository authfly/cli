package deploy

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Backup archive: "AFBK1\n" + 8-byte random nonce prefix, then chunks of [4-byte length][AES-256-GCM sealed data].
// Nonce = prefix || 4-byte chunk counter; the last chunk carries AAD "last" so truncation is detected.
const bkMagic, bkChunk = "AFBK1\n", 1 << 20

func (c *Config) backupAEAD() (cipher.AEAD, error) {
	k, err := c.Secret("backup_key")
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(k)
	if err != nil || len(key) != 32 {
		return nil, errors.New("backup_key must be 64 hex characters")
	}
	b, _ := aes.NewCipher(key)
	return cipher.NewGCM(b)
}

func encryptTo(w io.Writer, a cipher.AEAD, r io.Reader) error {
	prefix := make([]byte, 8)
	rand.Read(prefix)
	if _, err := w.Write(append([]byte(bkMagic), prefix...)); err != nil {
		return err
	}
	buf, next := make([]byte, bkChunk), make([]byte, bkChunk)
	n, err := io.ReadFull(r, buf)
	for i := uint32(0); ; i++ {
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			return err
		}
		m, err2 := io.ReadFull(r, next)
		last := m == 0
		nonce := binary.BigEndian.AppendUint32(append([]byte{}, prefix...), i)
		aad := []byte("more")
		if last {
			aad = []byte("last")
		}
		ct := a.Seal(nil, nonce, buf[:n], aad)
		if err := binary.Write(w, binary.BigEndian, uint32(len(ct))); err != nil {
			return err
		}
		if _, err := w.Write(ct); err != nil {
			return err
		}
		if last {
			return nil
		}
		buf, next, n, err = next, buf, m, err2
	}
}

func decryptFrom(r io.Reader, a cipher.AEAD) ([]byte, error) {
	head := make([]byte, len(bkMagic)+8)
	if _, err := io.ReadFull(r, head); err != nil || string(head[:len(bkMagic)]) != bkMagic {
		return nil, errors.New("not an authfly backup")
	}
	prefix := head[len(bkMagic):]
	var out bytes.Buffer
	for i := uint32(0); ; i++ {
		var l uint32
		if err := binary.Read(r, binary.BigEndian, &l); err != nil {
			return nil, errors.New("backup is truncated")
		}
		if l > bkChunk+64 {
			return nil, errors.New("backup is corrupt")
		}
		ct := make([]byte, l)
		if _, err := io.ReadFull(r, ct); err != nil {
			return nil, errors.New("backup is truncated")
		}
		nonce := binary.BigEndian.AppendUint32(append([]byte{}, prefix...), i)
		if pt, err := a.Open(nil, nonce, ct, []byte("last")); err == nil {
			out.Write(pt)
			return out.Bytes(), nil
		}
		pt, err := a.Open(nil, nonce, ct, []byte("more"))
		if err != nil {
			return nil, errors.New("backup does not decrypt: wrong backup_key or tampered file")
		}
		out.Write(pt)
	}
}

// Driver is what backup/upgrade need from a target.
type Driver interface {
	Deploy(rel *Release, p Pack) error
	Status() (string, error)
	Stop() error
	Start() error
	Dump(part string) ([]byte, error)
	Load(part string, data []byte) error
	Parts() []string
	Snapshot(tag string) error
	RestoreSnapshot(tag string) error
	Down(purge bool) error
}

func (c *Config) Driver() Driver {
	if c.Target == "incus" {
		return Incus{C: c}
	}
	return Docker{C: c}
}

func (c *Config) backupDir() string {
	d := c.Backup.Dir
	if !filepath.IsAbs(d) {
		d = filepath.Join(c.Dir(), d)
	}
	return d
}

// Backup stops the services briefly (consistent copy), dumps every data volume plus authfly.yaml into a tar,
// encrypts it with backup_key and writes <backup dir>/<name>-<time>.afbk (0600). Returns the file.
func (c *Config) MakeBackup(label string) (string, error) {
	a, err := c.backupAEAD()
	if err != nil {
		return "", err
	}
	d := c.Driver()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	add := func(name string, b []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: time.Now()}); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	y, _ := os.ReadFile(c.Path())
	add("authfly.yaml", y)
	st, _ := os.ReadFile(filepath.Join(c.State(), "state.json"))
	add("state.json", st)
	if err := d.Stop(); err != nil {
		return "", err
	}
	for _, p := range d.Parts() {
		b, err := d.Dump(p)
		if err != nil {
			d.Start()
			return "", fmt.Errorf("dump %s: %w", p, err)
		}
		add(p+".tar", b)
	}
	if err := d.Start(); err != nil {
		return "", err
	}
	tw.Close()
	os.MkdirAll(c.backupDir(), 0o700)
	if label == "" {
		label = "backup"
	}
	out := filepath.Join(c.backupDir(), fmt.Sprintf("%s-%s-%s.afbk", c.Name, label, time.Now().UTC().Format("20060102T150405Z")))
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := encryptTo(f, a, &raw); err != nil {
		return "", err
	}
	c.pruneBackups()
	return out, nil
}

func (c *Config) pruneBackups() {
	all, _ := filepath.Glob(filepath.Join(c.backupDir(), c.Name+"-backup-*.afbk"))
	sort.Strings(all)
	for len(all) > c.Backup.Keep {
		os.Remove(all[0])
		all = all[1:]
	}
}

// Restore decrypts an archive (authenticated: a wrong key or tampering fails before anything is touched), stops the
// services, replaces every data volume and starts again.
func (c *Config) RestoreBackup(file string) error {
	a, err := c.backupAEAD()
	if err != nil {
		return err
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := decryptFrom(f, a)
	if err != nil {
		return err
	}
	parts := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(tr)
		parts[h.Name] = b
	}
	d := c.Driver()
	if err := d.Stop(); err != nil {
		return err
	}
	for _, p := range d.Parts() {
		b, ok := parts[p+".tar"]
		if !ok {
			return fmt.Errorf("backup has no %s data", p)
		}
		if err := d.Load(p, b); err != nil {
			return fmt.Errorf("restore %s: %w", p, err)
		}
	}
	return d.Start()
}

// --- docker data parts ---

func (d Docker) Parts() []string { return []string{"stalwart", "authfly", "console"} }

func (d Docker) Dump(part string) ([]byte, error) {
	cmd := exec.Command("docker", "run", "--rm", "--network", "none", "-u", "0", "-v", d.volumes()[part]+":/v:ro", "alpine:3.22", "tar", "-C", "/v", "-cf", "-", ".")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%v: %s", err, errb.String())
	}
	return out.Bytes(), nil
}

func (d Docker) Load(part string, data []byte) error {
	cmd := exec.Command("docker", "run", "--rm", "-i", "--network", "none", "-u", "0", "-v", d.volumes()[part]+":/v", "alpine:3.22", "sh", "-c", "find /v -mindepth 1 -delete && tar -C /v -xpf -")
	cmd.Stdin = bytes.NewReader(data)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Snapshot (docker): an encrypted backup kept as the rollback point.
func (d Docker) Snapshot(tag string) error {
	f, err := d.C.MakeBackup("snapshot-" + tag)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(d.C.State(), "snapshot-"+tag), []byte(f), 0o600)
}

func (d Docker) RestoreSnapshot(tag string) error {
	f, err := os.ReadFile(filepath.Join(d.C.State(), "snapshot-"+tag))
	if err != nil {
		return fmt.Errorf("no snapshot %s: %w", tag, err)
	}
	return d.C.RestoreBackup(string(f))
}
