package rp

import "testing"

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{"/me": "/me", "/me?x=1": "/me?x=1", "": "", "//evil.com": "", "https://evil.com": "", "/\\evil.com": "", "me": "", "/a\r\nb": ""} {
		if got := SafeNext(in); got != want {
			t.Errorf("SafeNext(%q) = %q, want %q", in, got, want)
		}
	}
}
