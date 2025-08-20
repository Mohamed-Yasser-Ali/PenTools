# SpiderCo - Advanced Reconnaissance Tool

[![Go Install](https://img.shields.io/badge/go-install-blue.svg)](https://github.com/Mohamed-Yasser-Ali/PenTools)
[![Version](https://img.shields.io/badge/version-2.2.2-green.svg)](https://github.com/Mohamed-Yasser-Ali/PenTools/releases)

SpiderCo is a comprehensive reconnaissance tool designed for bug bounty hunters and penetration testers. It automates the process of subdomain enumeration, DNS resolution, HTTP probing, URL collection, directory fuzzing, port scanning, and vulnerability detection.

## 🚀 Installation

### Quick Install (Recommended)
```bash
go install github.com/Mohamed-Yasser-Ali/PenTools/cmd/spiderco@latest
```

### Manual Build
```bash
git clone https://github.com/Mohamed-Yasser-Ali/PenTools.git
cd PenTools
go build ./cmd/spiderco
```

## 🛠️ Prerequisites

SpiderCo leverages several popular tools. Install them as needed:

```bash
# Core tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Additional tools (optional)
go install github.com/tomnomnom/assetfinder@latest
go install github.com/owasp-amass/amass/v4/...@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
pip install waymore
pip install dirsearch

# System tools
sudo apt install curl jq  # For crt.sh integration
```

## 📖 Usage

### Basic Scan
```bash
spiderco -d example.com
```

### Full Reconnaissance
```bash
spiderco -d example.com --full
```

### Directory Fuzzing Only
```bash
spiderco -d example.com --fuzz
```

### Custom Options
```bash
spiderco -d example.com --threads 100 --resolvers resolvers.txt --ports --nuclei --fuzz
```

## 🎯 Features

### Core Modules
- **Subdomain Enumeration**: Multiple sources (subfinder, assetfinder, crt.sh, amass)
- **DNS Resolution**: Fast resolution with dnsx
- **HTTP Probing**: Live host detection with httpx
- **URL Collection**: Historical URLs from waybackurls, gau, and waymore
- **Directory Fuzzing**: Endpoint discovery with dirsearch (200, 301, 404 status codes)
- **Port Scanning**: Fast port discovery with naabu
- **Vulnerability Scanning**: Automated scanning with nuclei

### Data Sources
- **Subfinder**: Certificate transparency, DNS databases
- **Assetfinder**: Facebook, HackerTarget, and more
- **crt.sh**: Certificate transparency logs
- **Amass**: OSINT and active enumeration
- **Wayback Machine**: Historical URL data via waybackurls
- **Common Crawl**: Web crawl data via gau
- **Waymore**: Enhanced wayback machine data with filtering
- **Dirsearch**: Directory and file fuzzing with custom wordlists

## 📋 Command Line Options

```
Required:
  -d, --domain <domain>    Target domain

Options:
  -o, --output <dir>       Output directory (default: domain name)
  -t, --threads <n>        Number of threads (default: 50)
  --resolvers <file>       Custom DNS resolvers file
  --full                   Run all modules (includes fuzzing)
  --ports                  Enable port scanning
  --nuclei                 Enable nuclei scanning
  --fuzz                   Enable directory fuzzing with dirsearch
  --no-probe              Skip HTTP probing
  --no-urls               Skip URL collection
  --help                  Show help
  --version               Show version
```

## 📁 Output Structure

```
example.com/
├── enum/
│   ├── raw/                    # Raw tool outputs
│   │   ├── subfinder.txt
│   │   ├── assetfinder.txt
│   │   ├── crtsh.txt
│   │   └── amass.txt
│   ├── all_subdomains.txt      # Combined subdomains
│   └── resolved.txt            # Resolved subdomains
├── web/
│   ├── httpx_results.txt       # HTTP probe results
│   └── alive_hosts.txt         # Live hosts
├── urls/
│   ├── waybackurls.txt         # Historical URLs
│   ├── gau.txt                 # Archive URLs
│   ├── waymore.txt             # Enhanced wayback data
│   └── all_urls.txt            # Combined URLs
├── fuzzing/
│   ├── sub1.example.com.txt    # Raw dirsearch results
│   ├── sub2.example.com.txt    # Raw dirsearch results
│   ├── filtered_sub1.example.com.txt  # Filtered results (200,301,404)
│   └── filtered_sub2.example.com.txt  # Filtered results (200,301,404)
├── ports/
│   └── open_ports.txt          # Open ports
└── nuclei/
    └── vulnerabilities.txt     # Security findings
```

## 💡 Examples

### Bug Bounty Workflow
```bash
# Quick enumeration
spiderco -d target.com

# Full reconnaissance with custom resolvers and fuzzing
spiderco -d target.com --full --resolvers custom-resolvers.txt --threads 200

# Focused web application testing with fuzzing
spiderco -d target.com --fuzz --nuclei

# Directory fuzzing only on discovered hosts
spiderco -d target.com --fuzz --no-ports
```

### Custom Resolver Lists
```bash
# Use custom DNS resolvers for better results
spiderco -d example.com --resolvers resolvers.txt --fuzz
```

## 🔧 Configuration

### Custom Resolvers
Create a `resolvers.txt` file with one resolver per line:
```
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
```

### Performance Tuning
- Increase `--threads` for faster enumeration (default: 50)
- Use quality DNS resolvers for better resolution rates
- Directory fuzzing uses 20 threads per host for stability
- Consider rate limiting on shared infrastructure

### Dirsearch Configuration
The tool automatically:
- Tests both HTTP and HTTPS protocols
- Filters for interesting status codes (200, 301, 302, 404)
- Excludes 403 Forbidden responses from filtered results
- Uses random user agents to avoid detection
- Applies reasonable timeouts (10s) to prevent hanging

## 🔍 Fuzzing Features

### Smart Target Selection
- Uses alive hosts from HTTP probing when available
- Falls back to resolved subdomains if no alive hosts found
- Automatically handles HTTP/HTTPS protocol detection

### Output Organization
- Raw results: `fuzzing/subdomain.example.com.txt`
- Filtered results: `fuzzing/filtered_subdomain.example.com.txt`
- Only interesting status codes (200, 301, 404) in filtered files
- Per-subdomain organization for easy analysis

### Status Code Focus
- **200 OK**: Accessible endpoints and files
- **301/302 Redirects**: Potential interesting redirections
- **404 Not Found**: Confirms directory structure
- **Excludes 403**: Reduces noise from forbidden responses

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse of this tool.

## 🙏 Acknowledgments

- ProjectDiscovery for their amazing security tools
- Tom Hudson for assetfinder and waybackurls
- OWASP Amass team
- Maurosoria for dirsearch
- All other tool creators and contributors

---

**SpiderCo v2.2.2** - Now with intelligent directory fuzzing and enhanced endpoint discovery