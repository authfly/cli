package main

// Client of the Authfly internal admin API (server/web/gdpr.go AdminHandler): GDPR export and erasure, revocation,
// the Authfly audit log and retention. The console never writes Authfly's store itself.

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

func (c *Console) authfly(ctx context.Context, actor, method, path string, out any) (int, []byte, error) {
	req, _ := http.NewRequestWithContext(ctx, method, c.AuthflyURL+path, bytes.NewReader(nil))
	req.Header.Set("X-Authfly-Admin-Key", c.AuthflyKey)
	if actor != "" {
		req.Header.Set("X-Authfly-Actor", actor)
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
		return res.StatusCode, b, fmt.Errorf("authfly: HTTP %d %s", res.StatusCode, e.Error)
	}
	if out != nil {
		_ = json.Unmarshal(b, out)
	}
	return res.StatusCode, b, nil
}

func (c *Console) authflyPing(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, _, err := c.authfly(ctx, "", "GET", "/admin/v1/retention", nil)
	return err == nil
}

func pathAddr(a string) string { return url.PathEscape(a) }
