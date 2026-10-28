package core

import "testing"

func TestParseIdentifier(t *testing.T) {
	s := &Service{Cfg: Config{Domain: "cab.yself.link", UserDomainName: "cab.yself.link", OrgDomainName: "yself.link"}}
	cases := []struct {
		in, local, domain, kind string
		err                     error
	}{
		{"alice", "alice", "cab.yself.link", KindUser, nil},
		{"Alice", "alice", "cab.yself.link", KindUser, nil},
		{"alice@cab.yself.link", "alice", "cab.yself.link", KindUser, nil},
		{"ops@yself.link", "ops", "yself.link", KindOrg, nil},
		{"admin", "admin", "cab.yself.link", KindUser, nil},
		{"wmaster@yself.link", "wmaster", "yself.link", KindOrg, nil},
		{"postmaster", "postmaster", "cab.yself.link", KindUser, nil},
		{"a", "", "", "", ErrBadUsername},
		{"alice@evil.example", "", "", "", ErrOtherDomain},
	}
	for _, c := range cases {
		got, err := s.ParseIdentifier(c.in)
		if c.err != nil {
			if err != c.err {
				t.Errorf("%s: err %v want %v", c.in, err, c.err)
			}
			continue
		}
		if err != nil || got.Local != c.local || got.Domain != c.domain || got.Kind != c.kind {
			t.Errorf("%s: got %+v %v", c.in, got, err)
		}
	}
}

func TestIsReservedName(t *testing.T) {
	if !IsReservedName("Admin") || !IsReservedName("wmaster") || IsReservedName("alice") {
		t.Fatal("reserved list")
	}
}

func TestMirrorDomain(t *testing.T) {
	s := &Service{Cfg: Config{UserDomainName: "cab.yself.link", OrgDomainName: "yself.link"}}
	if s.MirrorDomain("cab.yself.link") != "yself.link" || s.MirrorDomain("yself.link") != "cab.yself.link" {
		t.Fatal(s.MirrorDomain("cab.yself.link"), s.MirrorDomain("yself.link"))
	}
}

func TestConfigDomains(t *testing.T) {
	c := Config{Domain: "example.test"}
	if got := c.Domains(); len(got) != 1 || got[0] != "example.test" {
		t.Fatalf("%v", got)
	}
	c.UserDomainName, c.OrgDomainName = "cab.yself.link", "yself.link"
	if got := c.Domains(); len(got) != 2 {
		t.Fatalf("%v", got)
	}
}

func TestParseMethods(t *testing.T) {
	if got := ParseMethods("password"); len(got) != 1 || got[0] != "password" {
		t.Fatalf("%v", got)
	}
	c := Config{Methods: ParseMethods("password")}
	if c.HasMethod("magic") || !c.HasMethod("password") {
		t.Fatal("password-only")
	}
	if !((Config{}).HasMethod("magic") && (Config{}).HasMethod("password")) {
		t.Fatal("empty Methods means both")
	}
}
