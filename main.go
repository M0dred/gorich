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
	OutputFormat       string
	Proxy              string
	Filename           string
	Concurrency        int
	InsecureSkipVerify bool
	Verbose            bool
}

func main() {
	var config Config
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	flag.BoolVar(verbose, "v", false, "(alias for -verbose)")

	flag.StringVar(&config.Filename, "filename", "", "File containing an IP per line. Use '-' for stdin.")
	flag.StringVar(&config.Filename, "f", "", "(alias for -filename)")

	flag.StringVar(&config.OutputFormat, "output", "shell", "Output format: shell, ndjson, json")
	flag.StringVar(&config.OutputFormat, "o", "shell", "(alias for -output)")

	flag.StringVar(&config.Proxy, "proxy", "", "Proxy URI (HTTP, HTTPS or SOCKS)")
	flag.StringVar(&config.Proxy, "p", "", "(alias for -proxy)")

	flag.IntVar(&config.Concurrency, "concurrency", defaultConcurrency, "Number of concurrent lookups")
	flag.IntVar(&config.Concurrency, "c", defaultConcurrency, "(alias for -concurrency)")

	flag.BoolVar(&config.InsecureSkipVerify, "insecure", false, "Skip TLS certificate verification (NOT RECOMMENDED)")
	flag.BoolVar(&config.InsecureSkipVerify, "i", false, "(alias for -insecure)")

	flag.Parse()

	// If the short alias was used, it will overwrite the long version if provided after it.
	// After parsing, ensure all alias logic is handled:
	config.Verbose = *verbose

	if config.Filename == "" {
		fmt.Fprintln(os.Stderr, "Error: Filename is required")
		os.Exit(exitErrorCode)
	}

	client, err := createHTTPClient(config.Proxy, config.InsecureSkipVerify)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating HTTP client: %s\n", err)
		os.Exit(exitErrorCode)
	}

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

	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipCh {
				host := fetchHostInfo(client, ip, config.Verbose)
				if host != nil {
					resultCh <- host
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	go func() {
		for scanner.Scan() {
			ip := scanner.Text()
			if isValidIP(ip) {
				ipCh <- ip
			} else if config.Verbose {
				fmt.Fprintf(os.Stderr, "Skipping invalid IP: %s\n", ip)
			}
		}
		if err := scanner.Err(); err != nil && config.Verbose {
			fmt.Fprintf(os.Stderr, "Error reading input: %s\n", err)
		}
		close(ipCh)
	}()

	processResults(resultCh, config.OutputFormat)
}

func openFile(filename string) (*os.File, error) {
	if filename == "-" {
		return os.Stdin, nil
	}
	return os.Open(filename)
}

func createHTTPClient(proxyURL string, insecureSkipVerify bool) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		},
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

func fetchHostInfo(client *http.Client, ip string, verbose bool) *Host {
	url := internetDBURL + ip
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating request for %s: %s\n", ip, err)
		return nil
	}

	req.Header.Set("User-Agent", defaultUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "Error fetching %s: %s\n", ip, err)
		}
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if verbose {
			fmt.Fprintf(os.Stderr, "Warning: Non-200 status for %s: %d\n", ip, resp.StatusCode)
		}
		return nil
	}

	var host Host
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "Error parsing JSON for %s: %s\n", ip, err)
		}
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
