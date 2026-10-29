package main

import (
	"bufio"
	"bytes"
	"errors"
	"image"
	"image/jpeg"
	"io"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	_ "image/gif"
	_ "image/png"

	"github.com/authfly/cli/server/core"
	"golang.org/x/image/draw"
	_ "golang.org/x/image/webp"
)

var handleRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,28})[a-z0-9]$`)

// routeNames can never be handles: they are (or may become) paths of the app.
var routeNames = map[string]bool{"me": true, "edit": true, "auth": true, "assets": true, "avatars": true, "healthz": true, "robots-txt": true,
	"favicon-ico": true, "static": true, "settings": true, "new": true, "about": true, "privacy": true, "terms": true, "legal": true, "u": true}

// reserved is AuthFly's reserved-names list (core.DefaultReservedNames + the AUTHFLY_RESERVED_NAMES_FILE lines).
var reserved = map[string]bool{}

func loadReserved(path string) {
	for _, n := range core.DefaultReservedNames {
		reserved[n] = true
	}
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.ToLower(strings.TrimSpace(sc.Text())); l != "" && !strings.HasPrefix(l, "#") {
			reserved[l] = true
		}
	}
}

var (
	errHandleFormat   = errors.New("handle.format")
	errHandleReserved = errors.New("handle.reserved")
	errHandleTaken    = errors.New("handle.taken")
)

// checkHandle: 3-30 chars of [a-z0-9-], no leading/trailing or double hyphen, not a route, not reserved — unless it
// is the user's own mailbox local part (AuthFly local parts are unique, so wmaster may use wmaster).
func checkHandle(h, ownLocal string) error {
	if !handleRe.MatchString(h) || strings.Contains(h, "--") {
		return errHandleFormat
	}
	if routeNames[h] {
		return errHandleReserved
	}
	if reserved[h] && h != ownLocal {
		return errHandleReserved
	}
	return nil
}

// defaultHandle derives a handle from the mailbox local part.
func defaultHandle(local string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(local) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '.' || r == '_':
			b.WriteRune('-')
		}
	}
	h := strings.Trim(b.String(), "-")
	for strings.Contains(h, "--") {
		h = strings.ReplaceAll(h, "--", "-")
	}
	if len(h) > 30 {
		h = strings.Trim(h[:30], "-")
	}
	return h
}

func localPart(email, preferred string) string {
	if preferred != "" && !strings.Contains(preferred, "@") {
		return strings.ToLower(preferred)
	}
	if i := strings.IndexByte(email, '@'); i > 0 {
		return strings.ToLower(email[:i])
	}
	return strings.ToLower(preferred)
}

var errURL = errors.New("link.url")

// cleanURL accepts https:// URLs with a host and mailto: with one valid address; everything else (javascript:,
// data:, http:, relative) is refused.
func cleanURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, " \t\r\n<>\"'`") {
		return "", errURL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errURL
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		if u.Host == "" || u.User != nil || strings.HasPrefix(u.Host, ".") {
			return "", errURL
		}
		u.Scheme = "https"
		return u.String(), nil
	case "mailto":
		addr := u.Opaque
		if i := strings.IndexByte(addr, '?'); i >= 0 {
			addr = addr[:i]
		}
		if a, err := mail.ParseAddress(addr); err != nil || a.Address != addr {
			return "", errURL
		}
		return "mailto:" + addr, nil
	}
	return "", errURL
}

// clip trims and cuts text to n runes; control characters (except newlines when multiline) are dropped.
func clip(s string, n int, multiline bool) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
	var b strings.Builder
	k := 0
	for _, r := range s {
		if k >= n {
			break
		}
		if r < 0x20 && !(multiline && r == '\n') || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		k++
	}
	return b.String()
}

func runes(s string) int { return utf8.RuneCountInString(s) }

// Icons offered for links (Lucide names, all present in the Authfly icon set).
var icons = []string{"", "link", "globe", "mail", "send", "message-circle", "phone", "camera", "film", "headphones", "newspaper", "book-open", "briefcase", "shopping-bag", "heart", "calendar", "map-pin", "code-xml", "rocket", "gift", "shield-check", "at-sign", "video"}

func validIcon(s string) bool {
	for _, i := range icons {
		if i == s {
			return true
		}
	}
	return false
}

var themes = []string{"light", "dark", "muted", "contrast"}
var buttonStyles = []string{"solid", "outline", "soft"}
var shapes = []string{"rounded", "pill", "square"}

func oneOf(v string, set []string) string {
	for _, s := range set {
		if v == s {
			return v
		}
	}
	return set[0]
}

const (
	maxAvatarBytes = 4 << 20
	maxAvatarPix   = 40_000_000 // decoded pixels (8000x5000); refuses decompression bombs before decoding
	avatarSize     = 256
	maxLinks       = 30
)

var errImage = errors.New("avatar.format")
var errImageBig = errors.New("avatar.big")

// processAvatar decodes JPEG/PNG/GIF/WebP, refuses huge dimensions, centre-crops to a square, resizes to 256x256 and
// re-encodes JPEG: metadata (EXIF, GPS, ICC, comments) never survives the re-encode.
func processAvatar(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxAvatarBytes+1))
	if err != nil {
		return nil, errImage
	}
	if len(data) > maxAvatarBytes {
		return nil, errImageBig
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, errImage
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width*cfg.Height > maxAvatarPix {
		return nil, errImageBig
	}
	src, format, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, errImage
	}
	if format == "jpeg" {
		src = orient(src, jpegOrientation(data)) // phone photos: rotate before crop, the tag itself is dropped
	}
	b := src.Bounds()
	side := min(b.Dx(), b.Dy())
	crop := image.Rect(b.Min.X+(b.Dx()-side)/2, b.Min.Y+(b.Dy()-side)/2, 0, 0)
	crop.Max = crop.Min.Add(image.Pt(side, side))
	dst := image.NewRGBA(image.Rect(0, 0, avatarSize, avatarSize))
	draw.Draw(dst, dst.Bounds(), image.White, image.Point{}, draw.Src) // transparent PNGs get a white background
	draw.CatmullRom.Scale(dst, dst.Bounds(), src, crop, draw.Over, nil)
	var out bytes.Buffer
	if err := jpeg.Encode(&out, dst, &jpeg.Options{Quality: 85}); err != nil {
		return nil, errImage
	}
	return out.Bytes(), nil
}

// initials for the fallback avatar.
func initials(name, handle string) string {
	src := strings.Fields(name)
	out := ""
	for _, w := range src {
		r, _ := utf8.DecodeRuneInString(w)
		out += strings.ToUpper(string(r))
		if runes(out) == 2 {
			break
		}
	}
	if out == "" && handle != "" {
		out = strings.ToUpper(handle[:1])
	}
	return out
}
