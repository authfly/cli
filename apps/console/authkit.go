package main

// Client of the Authkit internal admin API (server/web/gdpr.go AdminHandler): GDPR export and erasure, revocation,
// the Authkit audit log and retention. The console never writes Authkit's store itself.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

func (c *Console) authkit(ctx context.Context, actor, method, path string, out any) (int, []byte, error) {
	req, _ := http.NewRequestWithContext(ctx, method, c.AuthkitURL+path, bytes.NewReader(nil))
	req.Header.Set("X-Authkit-Admin-Key", c.AuthkitKey)
	if actor != "" {
		req.Header.Set("X-Authkit-Actor", actor)
	}
	res, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		return res.StatusCode, b, fmt.Errorf("authkit: HTTP %d %s", res.StatusCode, e.Error)
	}
	if out != nil {
		_ = json.Unmarshal(b, out)
	}
	return res.StatusCode, b, nil
}

func (c *Console) authkitPing(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, _, err := c.authkit(ctx, "", "GET", "/admin/v1/retention", nil)
	return err == nil
}

func pathAddr(a string) string { return url.PathEscape(a) }
