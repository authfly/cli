package deploy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Channel signatures (docs/release.md#signing).
//
// channel.json is published together with a detached channel.json.sig. The signature is Ed25519 (crypto/ed25519, no
// extra dependency) over the exact bytes of channel.json, so it covers the whole manifest — every release, file
// checksum and image digest in it — and needs no canonical JSON. Older CLIs (0.4.0) never fetch the .sig, so the same
// channel.json keeps working for them.
//
// channel.json.sig:
//
//	{"format": "authfly-channel-sig/1",
//	 "signatures": [{"key_id": "<16 hex>", "alg": "ed25519", "sig": "<base64>"}]}
//
// key_id is the first 8 bytes (16 hex digits) of sha256(public key). Rotation: a new key is added to TrustedKeys and
// shipped in a CLI release; the channel is then signed with the old and the new key (two entries) until the old key
// is dropped from TrustedKeys. One valid signature by a trusted key is enough; a bad signature by a trusted key is
// always refused, even when another one verifies.

// TrustedKeys: key id -> base64 Ed25519 public key. The private half is kept off the repository by the maintainer.
var TrustedKeys = map[string]string{
	"16c52cedac5309c6": "C9crAPhbreuhJCvNdJJviU8jNODb86g4h9LfRokx7F8=", // authfly release key 1 (2026-10)
}

// trustedKeys is what LoadManifest uses (tests swap it).
var trustedKeys = TrustedKeys

const SigFormat = "authfly-channel-sig/1"

// ErrChannelSignature marks every signature failure (missing, unknown key, tampered).
var ErrChannelSignature = errors.New("channel signature")

type ChannelSig struct {
	Format     string         `json:"format"`
	Signatures []SigSignature `json:"signatures"`
}

type SigSignature struct {
	KeyID string `json:"key_id"`
	Alg   string `json:"alg"`
	Sig   string `json:"sig"`
}

// KeyID is the id of an Ed25519 public key.
func KeyID(pub ed25519.PublicKey) string {
	s := sha256.Sum256(pub)
	return hex.EncodeToString(s[:8])
}

// Keyring decodes a key id -> base64 public key map, checking that every id matches its key.
func Keyring(m map[string]string) (map[string]ed25519.PublicKey, error) {
	out := map[string]ed25519.PublicKey{}
	for id, b64 := range m {
		b, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trusted key %s: not a base64 Ed25519 public key", id)
		}
		if KeyID(b) != id {
			return nil, fmt.Errorf("trusted key %s: id does not match the key (%s)", id, KeyID(b))
		}
		out[id] = b
	}
	return out, nil
}

// SignChannel returns channel.json.sig for data, one signature per key (rotation: old + new).
func SignChannel(data []byte, keys ...ed25519.PrivateKey) ([]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New("no signing key")
	}
	s := ChannelSig{Format: SigFormat}
	for _, k := range keys {
		pub := k.Public().(ed25519.PublicKey)
		s.Signatures = append(s.Signatures, SigSignature{KeyID(pub), "ed25519", base64.StdEncoding.EncodeToString(ed25519.Sign(k, data))})
	}
	b, err := json.MarshalIndent(s, "", "  ")
	return append(b, '\n'), err
}

// VerifyChannel checks channel.json.sig against data with the given keyring; it returns the id of the key that signed.
func VerifyChannel(data, sig []byte, keys map[string]ed25519.PublicKey) (string, error) {
	var s ChannelSig
	if err := json.Unmarshal(sig, &s); err != nil || s.Format != SigFormat || len(s.Signatures) == 0 {
		return "", fmt.Errorf("%w: channel.json.sig is not an %s file", ErrChannelSignature, SigFormat)
	}
	var good string
	var unknown []string
	for _, e := range s.Signatures {
		pub, ok := keys[e.KeyID]
		if !ok {
			unknown = append(unknown, e.KeyID)
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(e.Sig)
		if e.Alg != "ed25519" || err != nil || !ed25519.Verify(pub, data, raw) {
			return "", fmt.Errorf("%w: channel.json does not match its signature by key %s: the manifest was modified or corrupted; refusing to use it", ErrChannelSignature, e.KeyID)
		}
		good = e.KeyID
	}
	if good == "" {
		trusted := make([]string, 0, len(keys))
		for id := range keys {
			trusted = append(trusted, id)
		}
		slices.Sort(trusted)
		return "", fmt.Errorf("%w: channel.json is signed by unknown key id %s (this CLI trusts %s): update authfly (npx authfly@latest), or the channel is not an official one",
			ErrChannelSignature, strings.Join(unknown, ", "), strings.Join(trusted, ", "))
	}
	return good, nil
}

// ParsePrivateKey reads a PKCS#8 PEM Ed25519 private key (tools/channelsign keygen).
func ParsePrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, errors.New("signing key: not a PKCS#8 PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	ek, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signing key: not Ed25519")
	}
	return ek, nil
}
