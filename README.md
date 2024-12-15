# **gorich**

## **Overview**
This tool provides a high-performance solution to enrich IP address information by querying Shodan's **InternetDB API**. It supports bulk IP lookups, concurrent processing, and multiple output formats (`json`, `ndjson`, and `shell`). The tool is ideal for network reconnaissance, vulnerability analysis, and generating detailed insights about IP addresses.

**Inspired by**: [nrich](https://gitlab.com/shodan-public/nrich)

---

## **Features**
- **IP Enrichment**: Fetch detailed information, including open ports, vulnerabilities, tags, and associated CPEs.
- **Bulk Processing**: Process large lists of IPs with ease.
- **Concurrent Execution**: Utilize configurable concurrency to speed up lookups.
- **Proxy Support**: Query through HTTP/HTTPS/SOCKS proxies.
- **Flexible Output Formats**:
  - **JSON**: Standard JSON array output.
  - **NDJSON**: Newline-delimited JSON format for easy parsing.
  - **Shell**: Human-readable, color-coded output for the terminal.

---

## **Usage**

### **1. Installation**
1. Clone this repository:
   ```bash
   git clone https://github.com/M0dred/gorich.git
   cd gorich
   ```

2. Install dependencies and build:
   ```bash
   go build -o gorich main.go
   ```

### **2. Running the Tool**
Run the tool with the following options:

#### **Command-Line Arguments**
- `--filename`, `-f`: Path to the file containing IPs (one IP per line). Use `-` to read from stdin.
- `--output`, `-o`: Output format (`shell`, `json`, or `ndjson`).
- `--proxy`, `-p`: Proxy URL for requests (HTTP/HTTPS/SOCKS).
- `--concurrency`, `-c`: Number of concurrent lookups (default: 10).
- `--insecure`, `-i`: Skip TLS certificate verification (NOT RECOMMENDED).
- `--verbose`, `-v`: Enable verbose output (prints errors/warnings to stderr).

Use `--help` or `-h` to display all available options.

#### **Example Commands**
- **Basic IP Lookup (JSON Output)**:
  ```bash
  ./gorich -f ips.txt -o json
  ```
- **With Proxy Support (NDJSON Output)**:
  ```bash
  ./gorich -f ips.txt -p http://localhost:8080 -o ndjson
  ```
- **Streaming Input from stdin (Shell Output)**:
  ```bash
  cat ips.txt | ./gorich -f - -o shell
  ```
- **Increase Concurrency and Enable Verbose Logging**:
  ```bash
  ./gorich -f ips.txt -o json -c 20 -v
  ```
- **Skipping TLS Verification (Not Recommended)**:
  ```bash
  ./gorich -f ips.txt -o shell -i
  ```
