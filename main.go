package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultConcurrency = 10
	exitErrorCode      = 1
	internetDBURL      = "https://internetdb.shodan.io/"
	defaultUserAgent   = "nrich"
)

// Host represents the JSON structure returned by the InternetDB API.
type Host struct {
	CPEs      []string `json:"cpes"`
	Hostnames []string `json:"hostnames"`
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
}

type Config struct {
	OutputFormat string
	Proxy        string
	Filename     string
	Concurrency  int
}

func main() {
	// Parse command-line arguments
	output := flag.String("output", "shell", "Output format: shell, ndjson, json")
	proxy := flag.String("proxy", "", "Proxy URI (HTTP, HTTPS or SOCKS)")
	filename := flag.String("filename", "", "File containing an IP per line. Use '-' for stdin.")
	concurrency := flag.Int("concurrency", defaultConcurrency, "Number of concurrent lookups")
	flag.Parse()

	if *filename == "" {
		fmt.Fprintln(os.Stderr, "Error: Filename is required")
		os.Exit(exitErrorCode)
	}

	config := Config{
		OutputFormat: *output,
		Proxy:        *proxy,
		Filename:     *filename,
		Concurrency:  *concurrency,
	}

	// Create HTTP client
	client, err := createHTTPClient(config.Proxy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating HTTP client: %s\n", err)
		os.Exit(exitErrorCode)
	}

	// Open file or use stdin
	file, err := openFile(config.Filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %s\n", err)
		os.Exit(exitErrorCode)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	ipCh := make(chan string)
	resultCh := make(chan *Host)

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipCh {
				host := fetchHostInfo(client, ip)
				if host != nil {
					resultCh <- host
				}
			}
		}()
	}

	// Close resultCh after all workers are done
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Feed IPs to the workers
	go func() {
		for scanner.Scan() {
			ip := scanner.Text()
			if isValidIP(ip) {
				ipCh <- ip
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input: %s\n", err)
		}
		close(ipCh)
	}()

	// Process results and print according to the requested output format
	processResults(resultCh, config.OutputFormat)
}

func openFile(filename string) (*os.File, error) {
	if filename == "-" {
		return os.Stdin, nil
	}
	return os.Open(filename)
}

func createHTTPClient(proxyURL string) (*http.Client, error) {
	transport := &http.Transport{
		// Default: Verify TLS certificates for security.
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxy)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
	return client, nil
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func fetchHostInfo(client *http.Client, ip string) *Host {
	url := internetDBURL + ip
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating request for %s: %s\n", ip, err)
		return nil
	}

	req.Header.Set("User-Agent", defaultUserAgent)
	// Let the server decide encoding. We won't force Brotli.
	// req.Header.Set("Accept-Encoding", "br")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching %s: %s\n", ip, err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Non-200 means we got no data or an error from the server.
		// We'll just skip this IP.
		fmt.Fprintf(os.Stderr, "Warning: Non-200 status for %s: %d\n", ip, resp.StatusCode)
		return nil
	}

	var host Host
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON for %s: %s\n", ip, err)
		return nil
	}
	return &host
}

func processResults(results <-chan *Host, format string) {
	switch format {
	case "json":
		fmt.Println("[")
		processJSONResults(results)
		fmt.Println("]")
	case "ndjson":
		processNDJSONResults(results)
	default:
		processShellResults(results)
	}
}

func processJSONResults(results <-chan *Host) {
	first := true
	for host := range results {
		data, _ := json.Marshal(host)
		if !first {
			fmt.Print(",\n")
		}
		fmt.Print(string(data))
		first = false
	}
}

func processNDJSONResults(results <-chan *Host) {
	for host := range results {
		data, _ := json.Marshal(host)
		fmt.Println(string(data))
	}
}

func processShellResults(results <-chan *Host) {
	first := true
	for host := range results {
		if !first {
			fmt.Println()
		}
		first = false

		hostStr := host.IP
		if len(host.Hostnames) > 0 {
			hostStr += " (" + strings.Join(host.Hostnames, ", ") + ")"
		}
		fmt.Println(hostStr)

		if len(host.Ports) > 0 {
			fmt.Printf("  Ports: %v\n", host.Ports)
		}
		if len(host.Tags) > 0 {
			fmt.Printf("  Tags: %v\n", host.Tags)
		}
		if len(host.CPEs) > 0 {
			fmt.Printf("  CPEs: %v\n", host.CPEs)
		}
		if len(host.Vulns) > 0 {
			fmt.Printf("  Vulnerabilities: %v\n", host.Vulns)
		}
	}
}
