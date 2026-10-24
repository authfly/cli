package deploy

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Channel signatures (docs/release.md#signing).
//
// channel.json is published with a detached channel.json.sig in the SSHSIG format of OpenSSH (PROTOCOL.sshsig), as
// written by `ssh-keygen -Y sign -n authfly-channel -f <key> channel.json`. The release key is a FIDO2 security key
// (sk-ssh-ed25519@openssh.com on a YubiKey); plain ssh-ed25519 keys are accepted too (tests, a spare key). The
// signature covers the exact bytes of channel.json, so every release, checksum and image digest in it. CLIs up to
// 0.4.0 never fetch the .sig, so the same channel.json keeps working for them.
//
// channel.json.sig holds one or more armored SSHSIG blocks, one per signer (rotation: old + new key). Each block is
// exactly what ssh-keygen wrote; the release tool concatenates them. One valid signature by a trusted key is enough;
// a trusted key whose signature does not verify fails the whole channel; blocks by unknown keys are ignored as long
// as one trusted key signed.
//
// Checks per block, as `ssh-keygen -Y verify` does with an allowed_signers line `namespaces="authfly-channel"`:
// magic "SSHSIG", version 1, namespace authfly-channel, hash sha512, the embedded public key is a trusted key, the
// signature algorithm matches the key, and the signature verifies over the SSHSIG signed data. For sk keys the
// signature is ed25519 over sha256(application) || flags || counter || sha256(signed data), the application comes from
// the trusted public key, and the user-presence flag (touch) is required — stricter than `ssh-keygen -Y verify`, which
// only logs the flags for SSHSIG (sshd enforces touch for logins). The counter is reported but not enforced: OpenSSH
// keeps no counter state for SSHSIG either, and the CLI has no trusted store to compare it with.

// SigNamespace is the SSHSIG namespace of channel signatures (ssh-keygen -n).
const SigNamespace = "authfly-channel"

// TrustedKeys are the channel signing keys built into the CLI, in authorized_keys format.
var TrustedKeys = []string{
	// YubiKey Security Key NFC (FIDO2), resident, application ssh:authfly-release.
	// SHA256:dhhWLt7kJTEad+0i8nBdu8MHeA5SgPDYQNXQmL8oPGc
	"sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIEE96BHnD/bfSH23hMnp6FiXGdWq0sDOTZzZW4PUSCpEAAAAE3NzaDphdXRoZmx5LXJlbGVhc2U= authfly release",
}

// trustedKeys is what LoadManifest uses (tests and the authfly_e2ekeys build swap or extend it).
var trustedKeys = TrustedKeys

// ErrChannelSignature marks every signature failure (missing, unknown key, tampered, wrong namespace...).
var ErrChannelSignature = errors.New("channel signature")

const (
	sigMagic        = "SSHSIG"
	sigHash         = "sha512"
	skFlagUP   byte = 0x01 // user presence (touch)
	skFlagUV   byte = 0x04 // user verification (PIN)
	armorBegin      = "-----BEGIN SSH SIGNATURE-----"
	armorEnd        = "-----END SSH SIGNATURE-----"
)

// TrustedKey is a parsed TrustedKeys entry.
type TrustedKey struct {
	Key     ssh.PublicKey
	Comment string
}

func (k TrustedKey) Fingerprint() string { return ssh.FingerprintSHA256(k.Key) }

// Keyring parses authorized_keys lines; only ssh-ed25519 and sk-ssh-ed25519@openssh.com keys are accepted.
func Keyring(lines []string) ([]TrustedKey, error) {
	var out []TrustedKey
	for _, l := range lines {
		k, comment, opts, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err != nil {
			return nil, fmt.Errorf("trusted key %q: %w", l, err)
		}
		if len(opts) > 0 {
			return nil, fmt.Errorf("trusted key %s: options are not supported (%v)", ssh.FingerprintSHA256(k), opts)
		}
		switch k.Type() {
		case ssh.KeyAlgoED25519:
		case ssh.KeyAlgoSKED25519:
			if app := skApplication(k); !strings.HasPrefix(app, "ssh:") {
				return nil, fmt.Errorf("trusted key %s: FIDO application %q does not start with ssh:", ssh.FingerprintSHA256(k), app)
			}
		default:
			return nil, fmt.Errorf("trusted key %s: type %s is not allowed (ssh-ed25519 or sk-ssh-ed25519@openssh.com)", ssh.FingerprintSHA256(k), k.Type())
		}
		out = append(out, TrustedKey{k, comment})
	}
	return out, nil
}

// skApplication reads the FIDO application of an sk-ssh-ed25519 public key from its wire format.
func skApplication(k ssh.PublicKey) string {
	var w struct {
		Type, PubKey, Application string
	}
	if ssh.Unmarshal(k.Marshal(), &w) != nil {
		return ""
	}
	return w.Application
}

// AllowedSigners renders the keyring as an ssh-keygen allowed_signers file (principal authfly-release).
func AllowedSigners(keys []TrustedKey) string {
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "authfly-release namespaces=%q %s", SigNamespace, ssh.MarshalAuthorizedKey(k.Key))
	}
	return b.String()
}

// SSHSig is one decoded SSHSIG block (PROTOCOL.sshsig).
type SSHSig struct {
	PublicKey []byte
	Namespace string
	Reserved  string
	HashAlg   string
	Signature []byte
}

// SplitArmored returns every armored SSHSIG block of a .sig file, decoded.
func SplitArmored(sig []byte) ([][]byte, error) {
	var blobs [][]byte
	s := string(sig)
	for {
		i := strings.Index(s, armorBegin)
		if i < 0 {
			break
		}
		j := strings.Index(s[i:], armorEnd)
		if j < 0 {
			return nil, errors.New("unterminated SSH SIGNATURE block")
		}
		body := strings.Join(strings.Fields(s[i+len(armorBegin):i+j]), "")
		b, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			return nil, fmt.Errorf("SSH SIGNATURE block: %w", err)
		}
		blobs = append(blobs, b)
		s = s[i+j+len(armorEnd):]
	}
	if len(blobs) == 0 {
		return nil, errors.New("no -----BEGIN SSH SIGNATURE----- block")
	}
	return blobs, nil
}

// ParseSSHSig decodes the binary SSHSIG blob.
func ParseSSHSig(b []byte) (*SSHSig, error) {
	if !bytes.HasPrefix(b, []byte(sigMagic)) || len(b) < len(sigMagic)+4 {
		return nil, errors.New("not an SSHSIG blob")
	}
	b = b[len(sigMagic):]
	if v := binary.BigEndian.Uint32(b); v != 1 {
		return nil, fmt.Errorf("SSHSIG version %d, want 1", v)
	}
	var w struct {
		PublicKey []byte
		Namespace string
		Reserved  string
		HashAlg   string
		Signature []byte
	}
	if err := ssh.Unmarshal(b[4:], &w); err != nil { // Unmarshal also refuses trailing bytes
		return nil, fmt.Errorf("SSHSIG: %w", err)
	}
	s := SSHSig(w)
	return &s, nil
}

// signedData is the SSHSIG "signed data" structure for a message digest.
func signedData(namespace, reserved, hashAlg string, digest []byte) []byte {
	return append([]byte(sigMagic), ssh.Marshal(struct {
		Namespace, Reserved, HashAlg string
		Hash                         []byte
	}{namespace, reserved, hashAlg, digest})...)
}

// SignedData is the SSHSIG signed data of message in the channel namespace (what an SSH key signs; tests).
func SignedData(message []byte) []byte {
	h := sha512.Sum512(message)
	return signedData(SigNamespace, "", sigHash, h[:])
}

// verifyBlock checks one SSHSIG block against data and the trusted key it names.
func verifyBlock(data []byte, s *SSHSig, k TrustedKey) (string, error) {
	fp := k.Fingerprint()
	if s.Namespace != SigNamespace {
		return "", fmt.Errorf("signature by %s is for namespace %q, not %q", fp, s.Namespace, SigNamespace)
	}
	if s.HashAlg != sigHash {
		return "", fmt.Errorf("signature by %s uses hash %q, want %s", fp, s.HashAlg, sigHash)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(s.Signature, &sig); err != nil {
		return "", fmt.Errorf("signature by %s: %w", fp, err)
	}
	if sig.Format != k.Key.Type() {
		return "", fmt.Errorf("signature by %s: algorithm %s does not match the key type %s", fp, sig.Format, k.Key.Type())
	}
	detail := ""
	if k.Key.Type() == ssh.KeyAlgoSKED25519 {
		var sk struct {
			Flags   byte
			Counter uint32
		}
		if err := ssh.Unmarshal(sig.Rest, &sk); err != nil {
			return "", fmt.Errorf("signature by %s: FIDO flags/counter: %w", fp, err)
		}
		if sk.Flags&skFlagUP == 0 {
			return "", fmt.Errorf("signature by %s lacks user presence (the security key was not touched)", fp)
		}
		detail = ", touch"
		if sk.Flags&skFlagUV != 0 {
			detail += "+PIN"
		}
		detail += fmt.Sprintf(", counter %d", sk.Counter)
	} else if len(sig.Rest) > 0 {
		return "", fmt.Errorf("signature by %s: trailing data", fp)
	}
	h := sha512.Sum512(data)
	// x/crypto/ssh verifies ed25519 and sk-ed25519 (sha256(application)||flags||counter||sha256(msg)).
	if err := k.Key.Verify(signedData(s.Namespace, s.Reserved, s.HashAlg, h[:]), &sig); err != nil {
		return "", fmt.Errorf("channel.json does not match its signature by %s: the manifest was modified or corrupted (%v)", fp, err)
	}
	return detail, nil
}

// VerifyChannel checks channel.json.sig against data; it returns a description of the trusted key that signed.
func VerifyChannel(data, sig []byte, keys []TrustedKey) (string, error) {
	blobs, err := SplitArmored(sig)
	if err != nil {
		return "", fmt.Errorf("%w: channel.json.sig: %v", ErrChannelSignature, err)
	}
	var good []string
	var unknown []string
	for _, b := range blobs {
		s, err := ParseSSHSig(b)
		if err != nil {
			return "", fmt.Errorf("%w: channel.json.sig: %v", ErrChannelSignature, err)
		}
		pk, err := ssh.ParsePublicKey(s.PublicKey)
		if err != nil {
			return "", fmt.Errorf("%w: channel.json.sig: public key: %v", ErrChannelSignature, err)
		}
		i := slices.IndexFunc(keys, func(k TrustedKey) bool { return bytes.Equal(k.Key.Marshal(), pk.Marshal()) })
		if i < 0 {
			unknown = append(unknown, ssh.FingerprintSHA256(pk))
			continue
		}
		detail, err := verifyBlock(data, s, keys[i])
		if err != nil {
			return "", fmt.Errorf("%w: %v; refusing the channel", ErrChannelSignature, err)
		}
		good = append(good, fmt.Sprintf("%s %s (%s%s)", keys[i].Key.Type(), keys[i].Fingerprint(), keys[i].Comment, detail))
	}
	if len(good) == 0 {
		var trusted []string
		for _, k := range keys {
			trusted = append(trusted, k.Fingerprint())
		}
		return "", fmt.Errorf("%w: channel.json is signed by unknown key %s (this CLI trusts %s): update authfly (npx authfly@latest), or the channel is not an official one",
			ErrChannelSignature, strings.Join(unknown, ", "), strings.Join(trusted, ", "))
	}
	return strings.Join(good, "; "), nil
}

// ActiveTrustedKeys is the keyring this binary verifies with (TrustedKeys; plus the e2e key in authfly_e2ekeys builds).
func ActiveTrustedKeys() []string { return trustedKeys }
