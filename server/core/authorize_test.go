package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthorizeV1Body(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth" {
			t.Errorf("path %s", r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"authenticated","location":"https://app.example/cb?code=THECODE&state=s&iss=https://accounts.example"}`))
	}))
	defer srv.Close()
	sw := &Stalwart{BaseURL: srv.URL, HTTP: srv.Client()}
	res, err := sw.AuthorizeEx(context.Background(), AuthCodeRequest{
		AccountName: "alice@cab.yself.link", AccountSecret: "s3cret-s3cret",
		ClientID: "yself", RedirectURI: "https://yself.link/cb", Scope: "openid",
		Nonce: "n", State: "s", CodeChallenge: "challenge", Consent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Code != "THECODE" {
		t.Fatalf("code %q", res.Code)
	}
	if got["type"] != "authCode" || got["consent"] != true {
		t.Fatalf("body %+v", got)
	}
	if got["accountName"] != "alice@cab.yself.link" {
		t.Fatalf("accountName %v", got["accountName"])
	}
	if _, ok := got["clientId"]; ok {
		t.Fatalf("v0.16 clientId still sent: %+v", got)
	}
	q, _ := url.ParseQuery(got["query"].(string))
	if q.Get("client_id") != "yself" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != "challenge" {
		t.Fatalf("query %v", q)
	}
}

func TestAuthorizeMFARequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"type":"mfaRequired"}`))
	}))
	defer srv.Close()
	sw := &Stalwart{BaseURL: srv.URL, HTTP: srv.Client()}
	_, err := sw.Authorize(context.Background(), AuthCodeRequest{AccountName: "a@b", AccountSecret: "x", Query: "client_id=c", Consent: true})
	if err != ErrMFARequired {
		t.Fatalf("%v", err)
	}
}

func TestAuthorizeExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"type":"expired"}`))
	}))
	defer srv.Close()
	sw := &Stalwart{BaseURL: srv.URL, HTTP: srv.Client()}
	_, err := sw.Authorize(context.Background(), AuthCodeRequest{AccountName: "a@b", AccountSecret: "x", Query: "client_id=c", Consent: true})
	if err != ErrExpired {
		t.Fatalf("%v", err)
	}
}

func TestAuthorizeMFATokenForwarded(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		_, _ = w.Write([]byte(`{"type":"authenticated","location":"https://x/?code=c"}`))
	}))
	defer srv.Close()
	sw := &Stalwart{BaseURL: srv.URL, HTTP: srv.Client()}
	if _, err := sw.Authorize(context.Background(), AuthCodeRequest{
		AccountName: "a@b", AccountSecret: "x", MFAToken: "123456", Query: "client_id=c", Consent: true,
	}); err != nil {
		t.Fatal(err)
	}
	if got["mfaToken"] != "123456" {
		t.Fatalf("%+v", got)
	}
}

func TestSetPasswordPatchesOneCredential(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		calls = append(calls, string(b))
		if strings.Contains(string(b), "x:Account/get") {
			_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/get",{"list":[{"id":"A1","credentials":{"pw1":{"@type":"Password","secret":"****"},"ap1":{"@type":"AppPassword","description":"mail"}}}]},"g"]]}`))
			return
		}
		_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/set",{"updated":{"A1":null}},"u"]]}`))
	}))
	defer srv.Close()
	sw := &Stalwart{BaseURL: srv.URL, HTTP: srv.Client()}
	if err := sw.SetPassword(context.Background(), "A1", "new-password-ok"); err != nil {
		t.Fatal(err)
	}
	if len(calls) < 2 {
		t.Fatalf("calls %d", len(calls))
	}
	if !strings.Contains(calls[1], "credentials/pw1/secret") {
		t.Fatalf("did not patch the password credential: %s", calls[1])
	}
	if strings.Contains(calls[1], `"credentials":{"0"`) {
		t.Fatal("replaced the whole credentials list")
	}
}
