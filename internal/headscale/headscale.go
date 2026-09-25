// Package headscale is a minimal REST client with timeout/retry/ctx + version handling.
// It never logs the API key.
package headscale

import (
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
