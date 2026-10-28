package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseAliasesObjectAndArray(t *testing.T) {
	obj := parseAliases([]byte(`{"0":{"name":"alice","enable":false,"domainId":"D2"},"1":{"name":"bob","enable":true,"domainId":"D2"}}`))
	if len(obj) != 2 {
		t.Fatalf("object aliases %d", len(obj))
	}
	names := map[string]bool{}
	for _, a := range obj {
		names[a.Name] = true
	}
	if !names["alice"] || !names["bob"] {
		t.Fatalf("%+v", obj)
	}
	arr := parseAliases([]byte(`[{"name":"carol","enabled":false}]`))
	if len(arr) != 1 || arr[0].Name != "carol" {
		t.Fatalf("array %+v", arr)
	}
	if n := parseAliases([]byte(`null`)); len(n) != 0 {
		t.Fatalf("null %v", n)
	}
}

func TestCreateAccountKindMirrorUsesEnable(t *testing.T) {
	var lastSet string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(body, "x:Account/set") {
			lastSet = body
			_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/set",{"created":{"a":{"id":"A1"}}},"c"]]}`))
			return
		}
		if strings.Contains(body, "x:Domain/get") {
			_, _ = w.Write([]byte(`{"methodResponses":[["x:Domain/query",{"ids":["D1","D2"]},"q"],["x:Domain/get",{"list":[{"id":"D1","name":"cab.yself.link"},{"id":"D2","name":"yself.link"}]},"g"]]}`))
			return
		}
		_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/query",{"ids":[]},"q"],["x:Account/get",{"list":[]},"g"]]}`))
	}))
	defer srv.Close()
	sw := &Stalwart{BaseURL: srv.URL, HTTP: srv.Client()}
	sw.SetMirror("cab.yself.link", "yself.link")
	acc, err := sw.CreateAccountKind(context.Background(), "cab.yself.link", "alice", "password-ok-long", "Alice", KindUser)
	if err != nil {
		t.Fatal(err)
	}
	if acc.ID != "A1" {
		t.Fatalf("%+v", acc)
	}
	if !strings.Contains(lastSet, `"enable":false`) {
		t.Fatalf("expected enable:false, got %s", lastSet)
	}
	if strings.Contains(lastSet, `"enabled"`) {
		t.Fatalf("v0.16 enabled still sent: %s", lastSet)
	}
}

func TestNameTakenSeesObjectAliases(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(body, "x:Domain/get") {
			_, _ = w.Write([]byte(`{"methodResponses":[["x:Domain/query",{"ids":["D1"]},"q"],["x:Domain/get",{"list":[{"id":"D1","name":"cab.yself.link"}]},"g"]]}`))
			return
		}
		if strings.Contains(body, `"properties":["name","aliases","domainId"]`) || strings.Contains(body, `"aliases"`) && strings.Contains(body, "x:Account/get") {
			_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/query",{"ids":["A1"]},"q"],["x:Account/get",{"list":[{"name":"bob","aliases":{"0":{"name":"alice","enable":false,"domainId":"D2"}}}]},"g"]]}`))
			return
		}
		_, _ = w.Write([]byte(`{"methodResponses":[["x:Account/query",{"ids":[]},"q"],["x:Account/get",{"list":[]},"g"]]}`))
	}))
	defer srv.Close()
	sw := &Stalwart{BaseURL: srv.URL, HTTP: srv.Client()}
	taken, err := sw.NameTaken(context.Background(), "alice", "cab.yself.link")
	if err != nil {
		t.Fatal(err)
	}
	if !taken {
		t.Fatal("object alias alice was skipped")
	}
}

func TestJMAPListShapeRoundTrip(t *testing.T) {
	raw := json.RawMessage(`{"0":{"name":"alice","enable":false}}`)
	got := parseAliases(raw)
	if len(got) != 1 || got[0].Name != "alice" {
		t.Fatalf("%+v", got)
	}
}
