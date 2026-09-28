// Command meshbridge-agent: enroll, heartbeat (30s+jitter), probe, transfer
// executor, and the public-tunnel client (outbound-only).
// Agent dials Controller over HTTPS only; never requires inbound ports.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/meshbridge/meshbridge/internal/probe"
	"github.com/meshbridge/meshbridge/internal/transfer"
	"github.com/meshbridge/meshbridge/internal/tunnel"
)

type AgentConfig struct {
	Controller string
	DeviceID   string
	Token      string // enrollment or API token (never logged)
	Allowed    []string
	StateDir   string
}

const agentVersion = "0.2.0"

var httpClient = &http.Client{
	Timeout:   15 * time.Second,
	Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
}

func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int63n(int64(d)))
}

func runProbe(peer string) probe.Observation {
	// Prefer JSON status.
	if out, err := exec.Command("tailscale", "status", "--json").Output(); err == nil {
		if obs := probe.ClassifyStatusJSON(out, peer); obs.Class != probe.ClassUnknown {
			return obs
		}
	}
	if out, err := exec.Command("tailscale", "ping", "--c", "3", "--timeout", "5s", peer).CombinedOutput(); err != nil || len(out) > 0 {
		return probe.ParsePingOutput(string(out))
	} else {
		return probe.Observation{Class: probe.ClassUnreach}
	}
}

// heartbeat reports presence and returns the server's tunnel assignment.
func heartbeat(cfg AgentConfig, obs probe.Observation) ([]tunnel.AgentConfig, error) {
	body, _ := json.Marshal(map[string]any{
		"device_id":         cfg.DeviceID,
		"hostname":          hostname(),
		"os":                runtime.GOOS,
		"arch":              runtime.GOARCH,
		"agent_version":     agentVersion,
		"tailscale_version": tailscaleVersion(),
		"tailscale_ip":      tailscaleIP(),
		"probe":             obs,
		"time":              time.Now().UTC().Format(time.RFC3339),
	})
	req, _ := http.NewRequest("POST", cfg.Controller+"/api/v1/agents/heartbeat", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("heartbeat status %d", resp.StatusCode)
	}
	var out struct {
		Tunnels []tunnel.AgentConfig `json:"tunnels"`
	}
	_ = json.Unmarshal(raw, &out)
	return out.Tunnels, nil
}

func tailscaleIP() string {
	out, err := exec.Command("tailscale", "ip", "-4").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func tailscaleVersion() string {
	out, err := exec.Command("tailscale", "version").Output()
	if err != nil {
		return "unknown"
	}
	return string(bytes.TrimSpace(out))
}

func main() {
	var (
		controller  = flag.String("controller", "https://mesh.example.com", "controller base URL")
		deviceID    = flag.String("device-id", "", "device id")
		tokenFile   = flag.String("token-file", "", "file containing token (0600)")
		peer        = flag.String("probe-peer", "", "peer to probe (optional)")
		once        = flag.Bool("once", false, "single heartbeat then exit")
		allowedStr  = flag.String("allowed-roots", "", "comma-separated allowed roots")
		tunnelAllow = flag.String("tunnel-allow", "", "comma-separated extra CIDRs the tunnel client may dial (loopback is always allowed)")
	)
	flag.Parse()
	token := os.Getenv("MESH_TOKEN")
	if *tokenFile != "" {
		if raw, err := os.ReadFile(*tokenFile); err == nil {
			token = string(bytes.TrimSpace(raw))
		}
	}
	if *deviceID == "" || token == "" {
		log.Fatalf("device-id and token required (use --token-file with 0600)")
	}
	var allowed []string
	if *allowedStr != "" {
		for _, s := range bytes.Split([]byte(*allowedStr), []byte(",")) {
			allowed = append(allowed, string(bytes.TrimSpace(s)))
		}
	}
	cfg := AgentConfig{Controller: *controller, DeviceID: *deviceID, Token: token, Allowed: allowed}
	_ = transfer.DefChunk

	// Public tunnels: the controller's heartbeat response drives which
	// tunnels this agent maintains (--tunnel-allow bounds what it will dial).
	var cidrs []string
	if *tunnelAllow != "" {
		cidrs = strings.Split(*tunnelAllow, ",")
	}
	tunnelClient, err := tunnel.NewClient(*controller, token, cidrs)
	if err != nil {
		log.Fatalf("tunnel client: %v", err)
	}
	defer tunnelClient.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for {
		var obs probe.Observation
		if *peer != "" {
			obs = runProbe(*peer)
		} else {
			obs = probe.Observation{Class: probe.ClassUnknown}
		}
		if tunnels, err := heartbeat(cfg, obs); err != nil {
			log.Printf("heartbeat failed: %v", err)
		} else {
			log.Printf("heartbeat ok probe=%s tunnels=%d", obs.Class, len(tunnels))
			tunnelClient.Reconcile(ctx, tunnels)
		}
		if *once {
			return
		}
		select {
		case <-time.After(jitter(30 * time.Second)):
		case <-ctx.Done():
			log.Printf("shutting down")
			return
		}
	}
}
