package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGateMethodsHidesMagic(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "ok")
	})
	h := gateMethods("password", inner)
	r := httptest.NewRequest("GET", "/auth/magic", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("magic page %d", w.Code)
	}
	r = httptest.NewRequest("POST", "/api/v1/magic-link", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("magic api %d", w.Code)
	}
	r = httptest.NewRequest("GET", "/auth/sign-in", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("sign-in %d", w.Code)
	}
}
