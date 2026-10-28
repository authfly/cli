package core

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"strings"
)

// OAuthGrant is a connected application (Stalwart 1.0 x:OAuthGrant).
type OAuthGrant struct {
	ID         string         `json:"id"`
	AccountID  string         `json:"accountId"`
	ClientID   string         `json:"clientId"`
	ClientName string         `json:"clientName"`
	ClientKind string         `json:"clientKind"`
	Scopes     map[string]any `json:"scopes"`
	CreatedAt  string         `json:"createdAt"`
	LastUsedAt string         `json:"lastUsedAt"`
	Pending    bool           `json:"pending"`
}

// AppPassword is a secondary mail-client credential (x:AppPassword). The secret is
// only present on create.
type AppPassword struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Secret      string `json:"secret,omitempty"`
	CreatedAt   string `json:"createdAt"`
	ExpiresAt   string `json:"expiresAt,omitempty"`
}

// PasswordStatus is what x:AccountPassword/get returns (secret is masked).
type PasswordStatus struct {
	HasPassword bool
	TOTPEnabled bool
}

const singletonID = "singleton"

// CreateAccountKind creates a User account with a password and, when a mirror domain is
// configured, a disabled EmailAlias of the same local-part on that domain (shared name
// namespace). kind is KindUser or KindOrg and selects the primary domain.
func (s *Stalwart) CreateAccountKind(ctx context.Context, domain, name, password, fullName, kind string) (*Account, error) {
	if _, err := s.FindAccount(ctx, domain, name); err == nil {
		return nil, ErrAccountExists
	}
	did, err := s.EnsureDomain(ctx, domain)
	if err != nil {
		return nil, err
	}
	acc := map[string]any{
		"@type":            "User",
		"name":             name,
		"domainId":         did,
		"description":      fullName,
		"credentials":      map[string]any{"0": map[string]any{"@type": "Password", "secret": password}},
		"roles":            map[string]any{"@type": "User"},
		"permissions":      map[string]any{"@type": "Inherit"},
		"encryptionAtRest": map[string]any{"@type": "Disabled"},
	}
	if mirror := strings.TrimSpace(s.mirrorOf(domain)); mirror != "" {
		mid, err := s.EnsureDomain(ctx, mirror)
		if err != nil {
			return nil, err
		}
		acc["aliases"] = map[string]any{"0": map[string]any{
			"enabled": false, "name": name, "domainId": mid,
			"description": "namespace mirror",
		}}
	}
	r, err := s.JMAP(ctx, []any{"x:Account/set", map[string]any{"create": map[string]any{"a": acc}}, "c"})
	if err != nil {
		return nil, err
	}
	var set struct {
		Created    map[string]struct{ ID string } `json:"created"`
		NotCreated map[string]json.RawMessage     `json:"notCreated"`
	}
	_ = json.Unmarshal(r[0][1], &set)
	if set.Created["a"].ID == "" {
		return nil, fmt.Errorf("stalwart: account not created: %s", set.NotCreated["a"])
	}
	return &Account{ID: set.Created["a"].ID, Name: name, EmailAddress: name + "@" + domain, Description: fullName, DomainID: did}, nil
}

// mirrorOf is set by the service when dual-domain is on; empty means single-domain.
func (s *Stalwart) SetMirror(userDomain, orgDomain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userDomain, s.orgDomain = strings.ToLower(userDomain), strings.ToLower(orgDomain)
}

func (s *Stalwart) mirrorOf(domain string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := strings.ToLower(domain)
	if s.orgDomain == "" || s.orgDomain == s.userDomain {
		return ""
	}
	if d == s.userDomain {
		return s.orgDomain
	}
	if d == s.orgDomain {
		return s.userDomain
	}
	return ""
}

// FindAccountAny looks the local-part up in every given domain (exact name match).
func (s *Stalwart) FindAccountAny(ctx context.Context, name string, domains ...string) (*Account, error) {
	var last error
	for _, d := range domains {
		if d == "" {
			continue
		}
		acc, err := s.FindAccount(ctx, d, name)
		if err == nil {
			return acc, nil
		}
		if err != ErrNotFound {
			return nil, err
		}
		last = err
	}
	if last == nil {
		last = ErrNotFound
	}
	return nil, last
}

// NameTaken reports whether the local-part is already an account or a (mirror) alias in any domain.
func (s *Stalwart) NameTaken(ctx context.Context, name string, domains ...string) (bool, error) {
	if _, err := s.FindAccountAny(ctx, name, domains...); err == nil {
		return true, nil
	} else if err != ErrNotFound {
		return false, err
	}
	for _, d := range domains {
		if d == "" {
			continue
		}
		did, err := s.EnsureDomain(ctx, d)
		if err != nil {
			return false, err
		}
		// Broad account query then inspect aliases: v1 EmailAlias is nested on the account.
		r, err := s.JMAP(ctx, []any{"x:Account/query", map[string]any{"filter": map[string]any{"domainId": did}}, "q"},
			[]any{"x:Account/get", map[string]any{"#ids": map[string]any{"resultOf": "q", "name": "x:Account/query", "path": "/ids"},
				"properties": []string{"name", "aliases", "domainId"}}, "g"})
		if err != nil {
			return false, err
		}
		var got struct {
			List []struct {
				Name    string `json:"name"`
				Aliases []struct {
					Name     string `json:"name"`
					Enabled  bool   `json:"enabled"`
					DomainID string `json:"domainId"`
				} `json:"aliases"`
			} `json:"list"`
		}
		_ = json.Unmarshal(r[1][1], &got)
		for _, a := range got.List {
			if strings.EqualFold(a.Name, name) {
				return true, nil
			}
			for _, al := range a.Aliases {
				if strings.EqualFold(al.Name, name) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// ChangePassword sets a new password through x:AccountPassword (singleton) with currentSecret,
// so app passwords and TOTP on the account are left intact.
func (s *Stalwart) ChangePassword(ctx context.Context, accountID, current, next, otpCode string) error {
	body := map[string]any{"secret": next, "currentSecret": current}
	if otpCode != "" {
		body["otpAuth"] = map[string]any{"otpCode": otpCode}
	}
	return s.setAccountPassword(ctx, accountID, body)
}

// SetPassword resets the login password without the current secret (forgot-password). It patches
// only the Password credential, never replacing the credentials list.
func (s *Stalwart) SetPassword(ctx context.Context, id, password string) error {
	r, err := s.JMAP(ctx, []any{"x:Account/get", map[string]any{"ids": []string{id}, "properties": []string{"credentials"}}, "g"})
	if err != nil {
		return err
	}
	var got struct {
		List []struct {
			Credentials map[string]map[string]any `json:"credentials"`
		} `json:"list"`
	}
	_ = json.Unmarshal(r[0][1], &got)
	if len(got.List) == 0 {
		return ErrNotFound
	}
	credID := ""
	for cid, c := range got.List[0].Credentials {
		t, _ := c["@type"].(string)
		if strings.EqualFold(t, "Password") {
			credID = cid
			break
		}
	}
	if credID == "" {
		credID = "0"
	}
	patch := map[string]any{"credentials/" + credID + "/secret": password}
	ur, err := s.JMAP(ctx, []any{"x:Account/set", map[string]any{"update": map[string]any{id: patch}}, "u"})
	if err != nil {
		return err
	}
	var set struct {
		NotUpdated map[string]json.RawMessage `json:"notUpdated"`
	}
	_ = json.Unmarshal(ur[0][1], &set)
	if len(set.NotUpdated) > 0 {
		return fmt.Errorf("stalwart: password not updated: %s", set.NotUpdated[id])
	}
	return nil
}

func (s *Stalwart) setAccountPassword(ctx context.Context, accountID string, update map[string]any) error {
	r, err := s.JMAP(ctx, []any{"x:AccountPassword/set", map[string]any{
		"accountId": accountID,
		"update":    map[string]any{singletonID: update},
	}, "u"})
	if err != nil {
		return err
	}
	var set struct {
		NotUpdated map[string]json.RawMessage `json:"notUpdated"`
	}
	_ = json.Unmarshal(r[0][1], &set)
	if len(set.NotUpdated) > 0 {
		msg := string(set.NotUpdated[singletonID])
		low := strings.ToLower(msg)
		if strings.Contains(low, "current secret") || strings.Contains(low, "incorrect") {
			return ErrInvalidCredentials
		}
		if strings.Contains(low, "otp") || strings.Contains(low, "mfa") {
			return ErrMFARequired
		}
		return fmt.Errorf("stalwart: account password: %s", msg)
	}
	return nil
}

// PasswordStatus reads x:AccountPassword/get for the account (TOTP flag; secret is masked).
func (s *Stalwart) PasswordStatus(ctx context.Context, accountID string) (*PasswordStatus, error) {
	r, err := s.JMAP(ctx, []any{"x:AccountPassword/get", map[string]any{"accountId": accountID, "ids": []string{singletonID}}, "g"})
	if err != nil {
		return nil, err
	}
	var got struct {
		List []struct {
			Secret  string `json:"secret"`
			OtpAuth struct {
				OtpURL string `json:"otpUrl"`
			} `json:"otpAuth"`
		} `json:"list"`
	}
	_ = json.Unmarshal(r[0][1], &got)
	st := &PasswordStatus{}
	if len(got.List) > 0 {
		st.HasPassword = got.List[0].Secret != ""
		st.TOTPEnabled = got.List[0].OtpAuth.OtpURL != ""
	}
	return st, nil
}

// EnableTOTP writes an otpauth URL onto x:AccountPassword. current is the login password;
// otpCode is required when TOTP is already enabled. The returned URL is what the user scans.
func (s *Stalwart) EnableTOTP(ctx context.Context, accountID, accountName, current, otpCode string) (otpauth string, err error) {
	secret := totpSecret()
	otpauth = fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=YSELF&algorithm=SHA1&digits=6&period=30",
		strings.ReplaceAll(accountName, " ", "%20"), secret)
	body := map[string]any{"currentSecret": current, "otpAuth": map[string]any{"otpUrl": otpauth}}
	if otpCode != "" {
		body["otpAuth"].(map[string]any)["otpCode"] = otpCode
	}
	if err := s.setAccountPassword(ctx, accountID, body); err != nil {
		return "", err
	}
	return otpauth, nil
}

// DisableTOTP clears otpAuth. otpCode is the current TOTP code.
func (s *Stalwart) DisableTOTP(ctx context.Context, accountID, current, otpCode string) error {
	body := map[string]any{"currentSecret": current, "otpAuth": map[string]any{"otpUrl": nil, "otpCode": otpCode}}
	return s.setAccountPassword(ctx, accountID, body)
}

func totpSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return strings.TrimRight(base32.StdEncoding.EncodeToString(b), "=")
}

// UpdateProfile sets the display name (x:AccountSettings description).
func (s *Stalwart) UpdateProfile(ctx context.Context, accountID, fullName string) error {
	r, err := s.JMAP(ctx, []any{"x:AccountSettings/set", map[string]any{
		"accountId": accountID,
		"update":    map[string]any{singletonID: map[string]any{"description": fullName}},
	}, "u"})
	if err != nil {
		return err
	}
	var set struct {
		NotUpdated map[string]json.RawMessage `json:"notUpdated"`
	}
	_ = json.Unmarshal(r[0][1], &set)
	if len(set.NotUpdated) > 0 {
		return fmt.Errorf("stalwart: profile: %s", set.NotUpdated[singletonID])
	}
	return nil
}

// ListAppPasswords returns app passwords of the account (secrets masked).
func (s *Stalwart) ListAppPasswords(ctx context.Context, accountID string) ([]AppPassword, error) {
	r, err := s.JMAP(ctx, []any{"x:AppPassword/get", map[string]any{"accountId": accountID, "ids": nil}, "g"})
	if err != nil {
		return nil, err
	}
	var got struct {
		List []AppPassword `json:"list"`
	}
	_ = json.Unmarshal(r[0][1], &got)
	return got.List, nil
}

// CreateAppPassword creates an app password; the plaintext secret is only in this response.
func (s *Stalwart) CreateAppPassword(ctx context.Context, accountID, description string) (*AppPassword, error) {
	r, err := s.JMAP(ctx, []any{"x:AppPassword/set", map[string]any{
		"accountId": accountID,
		"create":    map[string]any{"ap": map[string]any{"description": description}},
	}, "c"})
	if err != nil {
		return nil, err
	}
	var set struct {
		Created    map[string]AppPassword     `json:"created"`
		NotCreated map[string]json.RawMessage `json:"notCreated"`
	}
	_ = json.Unmarshal(r[0][1], &set)
	ap := set.Created["ap"]
	if ap.ID == "" && ap.Secret == "" {
		return nil, fmt.Errorf("stalwart: app password not created: %s", set.NotCreated["ap"])
	}
	ap.Description = description
	return &ap, nil
}

// DestroyAppPassword revokes one app password.
func (s *Stalwart) DestroyAppPassword(ctx context.Context, accountID, id string) error {
	r, err := s.JMAP(ctx, []any{"x:AppPassword/set", map[string]any{
		"accountId": accountID, "destroy": []string{id},
	}, "d"})
	if err != nil {
		return err
	}
	return setOK(r, "app password")
}

// ListOAuthGrants lists connected applications (x:OAuthGrant) of the account.
func (s *Stalwart) ListOAuthGrants(ctx context.Context, accountID string) ([]OAuthGrant, error) {
	r, err := s.JMAP(ctx, []any{"x:OAuthGrant/query", map[string]any{"accountId": accountID, "filter": map[string]any{}}, "q"},
		[]any{"x:OAuthGrant/get", map[string]any{"accountId": accountID,
			"#ids": map[string]any{"resultOf": "q", "name": "x:OAuthGrant/query", "path": "/ids"}}, "g"})
	if err != nil {
		return nil, err
	}
	var got struct {
		List []OAuthGrant `json:"list"`
	}
	_ = json.Unmarshal(r[1][1], &got)
	return got.List, nil
}

// DestroyOAuthGrant revokes a connected application.
func (s *Stalwart) DestroyOAuthGrant(ctx context.Context, accountID, grantID string) error {
	r, err := s.JMAP(ctx, []any{"x:OAuthGrant/set", map[string]any{
		"accountId": accountID, "destroy": []string{grantID},
	}, "d"})
	if err != nil {
		return err
	}
	return setOK(r, "oauth grant")
}
