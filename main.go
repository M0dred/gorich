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
	concurrency      = 10
	exitErrorCode    = 1
	internetDBURL    = "https://internetdb.shodan.io/"
	defaultUserAgent = "nrich"
)

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
}

func main() {
	// Parse command-line arguments
	output := flag.String("output", "shell", "Output format (shell, ndjson, json)")
	proxy := flag.String("proxy", "", "Proxy URI (HTTP, HTTPS or SOCKS)")
	filename := flag.String("filename", "", "File containing an IP per line")
	flag.Parse()

	if *filename == "" {
		fmt.Println("Error: Filename is required")
		os.Exit(exitErrorCode)
	}

	config := Config{
		OutputFormat: *output,
		Proxy:        *proxy,
		Filename:     *filename,
	}

	// Create HTTP client
	client := createHTTPClient(config.Proxy)

	// Open file or use stdin
	file, err := openFile(config.Filename)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(exitErrorCode)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	ipCh := make(chan string)
	resultCh := make(chan *Host)

	var wg sync.WaitGroup
	wg.Add(concurrency)

	// Start workers
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			for ip := range ipCh {
				host := fetchHostInfo(client, ip)
				if host != nil { // Exclude nil responses caused by HTTP errors
					resultCh <- host
				}
			}
		}()
	}

	// Start a goroutine to close resultCh after all workers are done
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Read IPs and send to channel
	go func() {
		for scanner.Scan() {
			ip := scanner.Text()
			if isValidIP(ip) {
				ipCh <- ip
			}
		}
		close(ipCh)
	}()

	// Process results
	processResults(resultCh, config.OutputFormat)
}

func openFile(filename string) (*os.File, error) {
	if filename == "-" {
		return os.Stdin, nil
	}
	return os.Open(filename)
}

func createHTTPClient(proxyURL string) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Skip TLS certificate verification
		},
	}

	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			fmt.Printf("Error: Invalid proxy URL: %s\n", err)
			os.Exit(exitErrorCode)
		}
		transport.Proxy = http.ProxyURL(proxy)
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func fetchHostInfo(client *http.Client, ip string) *Host {
	url := internetDBURL + ip
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(exitErrorCode)
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Accept-Encoding", "br")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(exitErrorCode)
	}
	defer resp.Body.Close()

	// Skip processing if HTTP response status is not 200
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var host Host
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		fmt.Printf("Error: Failed to parse JSON for %s: %s\n", ip, err)
		return nil
	}
	return &host
}

func processResults(results <-chan *Host, format string) {
	if format == "json" {
		fmt.Println("[")
		defer fmt.Println("]")
	}

	first := true
	for host := range results {
		if host == nil {
			continue
		}

		switch format {
		case "ndjson":
			data, _ := json.Marshal(host)
			fmt.Println(string(data))
		case "json":
			if !first {
				fmt.Print(",\n")
			}
			data, _ := json.Marshal(host)
			fmt.Print(string(data))
			first = false
		default:
			printHostShell(host)
		}
	}
}

func printHostShell(host *Host) {
	fmt.Printf("%s (%s)\n", host.IP, strings.Join(host.Hostnames, ", "))
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
