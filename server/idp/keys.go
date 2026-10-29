package idp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Key is one ES256 key of the KeySet.
type Key struct {
	id   string
	priv *ecdsa.PrivateKey
}

func (k *Key) ID() string                                  { return k.id }
func (k *Key) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.ES256 }
func (k *Key) Algorithm() jose.SignatureAlgorithm          { return jose.ES256 }
func (k *Key) Use() string                                 { return "sig" }

// Key returns the private key for signing (SigningKey) — op.Key for JWKS publishing is pubKey below.
func (k *Key) Key() any { return k.priv }

type pubKey struct{ k *Key }

func (p pubKey) ID() string                         { return p.k.id }
func (p pubKey) Algorithm() jose.SignatureAlgorithm { return jose.ES256 }
func (p pubKey) Use() string                        { return "sig" }
func (p pubKey) Key() any                           { return &p.k.priv.PublicKey }

// KeySet is rotation-ready: the first key signs, every key (active + next + retired) is published in the JWKS.
type KeySet struct{ Keys []*Key }

func (ks *KeySet) Active() *Key { return ks.Keys[0] }

func (ks *KeySet) Public() []op.Key {
	out := make([]op.Key, 0, len(ks.Keys))
	for _, k := range ks.Keys {
		out = append(out, pubKey{k})
	}
	return out
}

// LoadKeySet reads PEM EC P-256 private keys; the first path is the active key. With create set, a missing first
// file is generated (0600).
func LoadKeySet(paths []string, create bool) (*KeySet, error) {
	ks := &KeySet{}
	for i, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		b, err := os.ReadFile(p)
		if os.IsNotExist(err) && i == 0 && create {
			if b, err = GenerateKeyPEM(); err == nil {
				err = os.WriteFile(p, b, 0o600)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("idp key %s: %w", p, err)
		}
		k, err := ParseKey(b)
		if err != nil {
			return nil, fmt.Errorf("idp key %s: %w", p, err)
		}
		ks.Keys = append(ks.Keys, k)
	}
	if len(ks.Keys) == 0 {
		return nil, errors.New("idp: no signing key")
	}
	return ks, nil
}

func GenerateKeyPEM() ([]byte, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func ParseKey(b []byte) (*Key, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	var priv *ecdsa.PrivateKey
	if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		priv = k
	} else if k8, err2 := x509.ParsePKCS8PrivateKey(blk.Bytes); err2 == nil {
		ek, ok := k8.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an EC key")
		}
		priv = ek
	} else {
		return nil, err
	}
	if priv.Curve != elliptic.P256() {
		return nil, errors.New("ES256 needs P-256")
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	h := sha256.Sum256(der)
	return &Key{id: "af-" + base64.RawURLEncoding.EncodeToString(h[:9]), priv: priv}, nil
}
