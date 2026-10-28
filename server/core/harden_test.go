package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsSchemaError(t *testing.T) {
	if !IsSchemaError(errors.New(`application: notUpdated {"app1":{"type":"invalidProperties","properties":["enabled"]}}`)) {
		t.Fatal("invalidProperties")
	}
	if !IsSchemaError(errors.New("unknown property anonymousClientRegistration")) {
		t.Fatal("unknown property")
	}
	if IsSchemaError(errors.New("connection refused")) {
		t.Fatal("connection refused is not schema")
	}
	if IsSchemaError(nil) {
		t.Fatal("nil")
	}
}

func TestRetryHardenStopsOnSchema(t *testing.T) {
	n := 0
	err := RetryHarden(30, time.Hour, func() error {
		n++
		return errors.New(`oidc: notUpdated {"singleton":{"type":"invalidProperties","properties":["anonymousClientRegistration"]}}`)
	})
	if err == nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestIsAuthError(t *testing.T) {
	if !IsAuthError(errors.New("stalwart jmap: http 401: Unauthorized")) {
		t.Fatal("401")
	}
	if !IsAuthError(errors.New("stalwart jmap: http 403: Forbidden")) {
		t.Fatal("403")
	}
	if !IsAuthError(errors.New(`stalwart jmap error: {"type":"forbidden"}`)) {
		t.Fatal("forbidden")
	}
	if IsAuthError(errors.New("connection refused")) {
		t.Fatal("connection refused is not auth")
	}
	if !HardenGiveUp(errors.New("stalwart jmap: http 401: x")) {
		t.Fatal("give up 401")
	}
	if HardenGiveUp(errors.New("connection refused")) {
		t.Fatal("should retry connection refused")
	}
}

func TestRetryHardenStopsOn401(t *testing.T) {
	n := 0
	err := RetryHarden(30, time.Hour, func() error {
		n++
		return errors.New("stalwart jmap: http 401: Unauthorized")
	})
	if n != 1 {
		t.Fatalf("retried 401 n=%d", n)
	}
	if err == nil || !strings.Contains(err.Error(), "admin credential") {
		t.Fatalf("want a clear auth message, got %v", err)
	}
}

func TestRetryHardenStopsOnForbidden(t *testing.T) {
	n := 0
	err := RetryHarden(30, 0, func() error {
		n++
		return errors.New("stalwart jmap: http 403: Forbidden")
	})
	if n != 1 || err == nil {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestRetryHardenRetriesOtherErrors(t *testing.T) {
	n := 0
	err := RetryHarden(3, 0, func() error {
		n++
		return errors.New("connection refused")
	})
	if err == nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestHardenUsesStalwart10PropertyNames(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		var in struct {
			MethodCalls [][]json.RawMessage `json:"methodCalls"`
		}
		_ = json.Unmarshal(b, &in)
		var out [][]any
		for _, c := range in.MethodCalls {
			var name, tag string
			_ = json.Unmarshal(c[0], &name)
			if len(c) > 2 {
				_ = json.Unmarshal(c[2], &tag)
			}
			res := map[string]any{"list": []any{}, "ids": []any{}, "created": map[string]any{}, "updated": map[string]any{"singleton": nil}}
			switch {
			case strings.HasPrefix(name, "x:Role"):
				res["list"] = []any{map[string]any{"id": "U", "description": "User"}}
				res["created"] = map[string]any{"r": map[string]any{"id": "Rsvc"}}
			case strings.HasPrefix(name, "x:Domain") && strings.Contains(name, "get"):
				res["list"] = []any{map[string]any{"id": "D1", "name": "cab.yself.link"}}
			case strings.HasPrefix(name, "x:Application"):
				res["list"] = []any{map[string]any{"id": "APP1", "description": "Webadmin", "enable": true}}
			case strings.HasPrefix(name, "x:Account") && strings.Contains(name, "set"):
				res["created"] = map[string]any{"s": map[string]any{"id": "S1"}}
			case strings.HasPrefix(name, "x:OAuthClient") && strings.Contains(name, "set"):
				res["created"] = map[string]any{"c": map[string]any{"id": "C1"}}
			}
			out = append(out, []any{name, res, tag})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"methodResponses": out})
	}))
	defer srv.Close()
	sw := &Stalwart{BaseURL: srv.URL, HTTP: srv.Client()}
	log, err := sw.Harden(context.Background(), HardenOptions{
		Domain: "cab.yself.link", ServiceName: "authfly-svc", ServicePassword: "sixteen-chars-ok",
		Clients: []OAuthClient{{ID: "authfly", Name: "Authfly", RedirectURIs: []string{"https://x/cb"}, FirstParty: true}},
	})
	if err != nil {
		t.Fatal(err, log)
	}
	joined := strings.Join(bodies, "\n")
	appSet := false
	for _, b := range bodies {
		if strings.Contains(b, "x:Application/set") {
			appSet = true
			if !strings.Contains(b, `"enable":false`) {
				t.Fatalf("Application.enable=false missing: %s", b)
			}
			if strings.Contains(b, `"enabled"`) {
				t.Fatalf("v0.16 Application.enabled still sent: %s", b)
			}
		}
	}
	if !appSet {
		t.Fatalf("no x:Application/set in %s", joined)
	}
	if !strings.Contains(joined, `"clientMetadataDocuments":"disabled"`) {
		t.Fatalf("OidcProvider.clientMetadataDocuments missing: %s", joined)
	}
	if strings.Contains(joined, "anonymousClientRegistration") || strings.Contains(joined, "requireClientRegistration") {
		t.Fatalf("v0.16 OidcProvider fields still sent")
	}
}
