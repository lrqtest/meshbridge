// Command meshbridge-cli: human+json output for projects/devices/transfers/relays/health + policy admin.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

var (
	base  = flag.String("server", "https://mesh.example.com", "server base URL")
	token = flag.String("token", os.Getenv("MESH_TOKEN"), "api token")
	jsonOut = flag.Bool("json", false, "json output")
)

func req(method, path string, body any) ([]byte, error) {
	var r io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	hreq, _ := http.NewRequest(method, *base+path, r)
	hreq.Header.Set("Authorization", "Bearer "+*token)
	if body != nil {
		hreq.Header.Set("Content-Type", "application/json")
	}
	cl := &http.Client{Timeout: 15 * time.Second}
	resp, err := cl.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(raw))
	}
	return raw, nil
}

func emit(raw []byte) {
	if *jsonOut {
		fmt.Println(string(raw))
		return
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		fmt.Println(string(raw))
		return
	}
	pretty, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(pretty))
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: meshbridge-cli [--server URL] [--token T] [--json] <projects list|devices list|devices show|transfer create|transfer list|transfer show|transfer pause|transfer resume|transfer cancel|relay list|health|admin policy render|admin policy check>")
		os.Exit(2)
	}
	if *token == "" && !(len(args) == 1 && args[0] == "health") {
		fmt.Fprintln(os.Stderr, "token required (--token or MESH_TOKEN)")
		os.Exit(2)
	}
	cmd := args[0]
	switch cmd {
	case "health":
		raw, err := req("GET", "/api/v1/health", nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		emit(raw)
	case "projects":
		raw, err := req("GET", "/api/v1/projects?limit=100", nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		emit(raw)
	case "devices":
		raw, err := req("GET", "/api/v1/devices?limit=100", nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		emit(raw)
	case "transfer":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "transfer <create|list>")
			os.Exit(2)
		}
		if args[1] == "list" {
			raw, err := req("GET", "/api/v1/transfers?limit=100", nil)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			emit(raw)
			return
		}
		fmt.Fprintln(os.Stderr, "use API for create/pause/resume in MVP (see docs)")
		os.Exit(2)
	case "relay":
		raw, err := req("GET", "/api/v1/relays", nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		emit(raw)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		os.Exit(2)
	}
}
