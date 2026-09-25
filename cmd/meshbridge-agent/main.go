// Command meshbridge-agent: enroll, heartbeat (30s+jitter), probe, transfer executor.
// Agent dials Controller over HTTPS only; never requires inbound ports.
package main

import (
	"bytes"
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
	"runtime"
	"strings"
	"time"

	"github.com/meshbridge/meshbridge/internal/probe"
	"github.com/meshbridge/meshbridge/internal/transfer"
)

type AgentConfig struct {
	Controller string
	DeviceID   string
	Token      string // enrollment or API token (never logged)
	Allowed    []string
	StateDir   string
}

const agentVersion = "0.1.0"

var httpClient = &http.Client{
	Timeout: 15 * time.Second,
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
	if out, err := exec.Command("tailscale", "ping", "--c", "3", "--timeout", "5s", peer).CombinedOutput(); err == nil || len(out) > 0 {
		return probe.ParsePingOutput(string(out))
	} else {
		return probe.Observation{Class: probe.ClassUnreach}
	}
}

func heartbeat(cfg AgentConfig, obs probe.Observation) error {
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
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("heartbeat status %d", resp.StatusCode)
	}
	return nil
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
		controller = flag.String("controller", "https://mesh.example.com", "controller base URL")
		deviceID   = flag.String("device-id", "", "device id")
		tokenFile  = flag.String("token-file", "", "file containing token (0600)")
		peer       = flag.String("probe-peer", "", "peer to probe (optional)")
		once       = flag.Bool("once", false, "single heartbeat then exit")
		allowedStr = flag.String("allowed-roots", "", "comma-separated allowed roots")
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
	for {
		var obs probe.Observation
		if *peer != "" {
			obs = runProbe(*peer)
		} else {
			obs = probe.Observation{Class: probe.ClassUnknown}
		}
		if err := heartbeat(cfg, obs); err != nil {
			log.Printf("heartbeat failed: %v", err)
		} else {
			log.Printf("heartbeat ok probe=%s", obs.Class)
		}
		if *once {
			return
		}
		time.Sleep(jitter(30 * time.Second))
	}
}
