// Package headscale is a minimal REST client with timeout/retry/ctx + version handling.
// It never logs the API key.
package headscale

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

func New(baseURL, apiKey string) *Client {
	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

type Node struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	IP   string   `json:"ip"`
	Tags []string `json:"tags"`
}

func (c *Client) do(ctx context.Context, method, path string, out any) error {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, nil)
		if err != nil {
			return err
		}
		if c.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+c.APIKey)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			last = err
			time.Sleep(time.Duration(attempt+1) * 300 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			last = fmt.Errorf("headscale %s %s: status %d", method, path, resp.StatusCode)
			if resp.StatusCode >= 500 {
				time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
				continue
			}
			return last
		}
		if out != nil {
			if err := json.Unmarshal(body, out); err != nil {
				return fmt.Errorf("decode: %w", err)
			}
		}
		return nil
	}
	return fmt.Errorf("headscale request failed after retries: %w", last)
}

// Health checks connectivity without exposing secrets.
func (c *Client) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	return c.do(ctx, "GET", "/api/v1/health", nil)
}

// ListNodes is a thin wrapper; real Headscale API shape may vary by version —
// callers must handle unknown fields gracefully (see docs).
func (c *Client) ListNodes(ctx context.Context) ([]Node, error) {
	var v struct {
		Nodes []Node `json:"nodes"`
	}
	if err := c.do(ctx, "GET", "/api/v1/node", &v); err != nil {
		return nil, err
	}
	return v.Nodes, nil
}

type User struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ListUsers tolerates both gateway casings seen across 0.2x/0.29.
func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	var v struct {
		Users []User `json:"users"`
	}
	if err := c.do(ctx, "GET", "/api/v1/user", &v); err != nil {
		return nil, err
	}
	return v.Users, nil
}

// CreateUser returns the user id; idempotent — resolve before create
// (Headscale 0.29 happily creates duplicate-numbered users on re-POST).
func (c *Client) CreateUser(ctx context.Context, name string) (string, error) {
	if users, err := c.ListUsers(ctx); err == nil {
		for _, u := range users {
			if u.Name == name {
				return u.ID, nil
			}
		}
	}
	if err := c.do(ctx, "POST", "/api/v1/user", map[string]any{"name": name}); err != nil {
		// lost a race or casing quirk: resolve once more before failing
		if users, lerr := c.ListUsers(ctx); lerr == nil {
			for _, u := range users {
				if u.Name == name {
					return u.ID, nil
				}
			}
		}
		return "", err
	}
	users, err := c.ListUsers(ctx)
	if err != nil {
		return "", err
	}
	for _, u := range users {
		if u.Name == name {
			return u.ID, nil
		}
	}
	return "", fmt.Errorf("user %q created but not listed", name)
}

// CreatePreAuthKey returns the full key (shown once).
func (c *Client) CreatePreAuthKey(ctx context.Context, userID string, reusable bool, expiration time.Time) (string, error) {
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		body := map[string]any{
			"user":      userID,
			"reusable":  reusable,
			"ephemeral": false,
		}
		if !expiration.IsZero() {
			body["expiration"] = expiration.Format(time.RFC3339Nano)
		}
		var raw json.RawMessage
		req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/api/v1/preauthkey", nil)
		if err != nil {
			return "", err
		}
		if c.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+c.APIKey)
		}
		payload, _ := json.Marshal(body)
		req.Body = io.NopCloser(bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			last = err
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			last = fmt.Errorf("create preauthkey: status %d", resp.StatusCode)
			if resp.StatusCode >= 500 {
				time.Sleep(300 * time.Millisecond)
				continue
			}
			return "", last
		}
		raw = b
		var v struct {
			PreAuthKey *struct {
				Key string `json:"key"`
			} `json:"preAuthKey"`
			PreAuthKeySnake *struct {
				Key string `json:"key"`
			} `json:"pre_auth_key"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return "", err
		}
		if v.PreAuthKey != nil && v.PreAuthKey.Key != "" {
			return v.PreAuthKey.Key, nil
		}
		if v.PreAuthKeySnake != nil && v.PreAuthKeySnake.Key != "" {
			return v.PreAuthKeySnake.Key, nil
		}
		return "", fmt.Errorf("no key in response")
	}
	return "", last
}
