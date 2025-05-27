# BBScanner -  Web Security Scanner

BBScanner is an advanced web security scanning tool that automates various reconnaissance and vulnerability assessment tasks. It combines multiple security tools into a single, efficient workflow.

## Features

- **Subdomain Enumeration**: Using subfinder, assetfinder, and shuffledns
- **HTTP Probe**: Live host detection with httpx
- **URL Discovery**: 
  - Wayback machine data collection
  - Katana web crawling
  - Directory bruteforcing with gobuster
- **Vulnerability Scanning**:
  - Pattern matching with gf
  - Nuclei scanning
  - Optional Nessus integration
- **Resume Capability**: Supports resuming interrupted scans
- **Proxy Support**: Built-in Burp Suite integration
- **Result Management**: Organized output structure and summary reports

## Prerequisites

The following tools must be installed and available in your PATH:

- subfinder
- assetfinder
- shuffledns
- httpx
- waybackurls
- gobuster
- gf
- qsreplace
- nuclei
- katana
- curl
- jq

Additional requirements:
- dns-resolvers.txt file
- SecLists wordlists

## Usage

Basic usage:
```bash
./bbscanner.sh -d example.com http://burp:8080
./bbscanner.sh -d example.com --skip-burp
```

With domain list:
```bash
./bbscanner.sh -l domains.txt http://burp:8080
```

Available options:
```
Options:
  -h, --help           Show help message
  -d <domain>          Single domain to scan
  -l <domain_list>     File containing list of domains
  --skip-subdomain     Skip subdomain enumeration
  --skip-http          Skip HTTP probe
  --skip-wayback       Skip wayback URL collection
  --skip-crawl         Skip crawling
  --skip-dirb          Skip directory bruteforcing
  --skip-gf            Skip pattern matching
  --skip-nuclei        Skip nuclei scanning
  --skip-burp          Skip sending URLs to Burp Suite
  --with-nessus        Enable Nessus integration
  --nessus-user USER   Nessus username
  --nessus-pass PASS   Nessus password
  --force-rescan       Force rescan, ignore existing results
```

## Output Structure

Results are organized in domain-specific directories:
```
example.com.monascanner/
├── subdomains              # Subdomain enumeration results
├── httpx                   # Live HTTP endpoints
├── waybacksorted          # Wayback machine URLs
├── katana_results         # Crawling results
├── gobuster_results       # Directory bruteforce results
├── gfcikti               # Pattern matching results
├── nuclei_results/        # Nuclei scan findings
├── merged_results/        # Combined results
│   ├── all_urls.txt
│   └── all_findings.txt
└── SUMMARY.md            # Scan summary and statistics
```

## Resume Functionality

BBScanner supports resuming interrupted scans. If a scan is interrupted, running the same command will:
- Skip completed modules
- Resume from the last successful point
- Use existing results for dependent modules

Use `--force-rescan` to ignore existing results and start fresh.

## Security Considerations

- Always obtain proper authorization before scanning any target
- Be mindful of rate limiting and resource usage
- Use with caution on production systems
- Follow responsible disclosure practices

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 
