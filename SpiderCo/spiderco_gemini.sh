#!/bin/bash

# SpiderCo - Advanced Reconnaissance Tool
# Author: Mohamed-Yasser-Ali
# Version: 2.2.2 (Final Refined Version)

set -euo pipefail

VERSION="2.2.2"
# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
success() { echo -e "${GREEN}[DONE]${NC} $1"; }

# Help
show_help() {
    cat << EOF
SpiderCo v$VERSION - Advanced Reconnaissance Tool

Usage: $0 -d <domain> [options]

Required:
  -d, --domain <domain>    Target domain

Options:
  -o, --output <dir>       Output directory (default: domain name)
  -t, --threads <n>        Number of threads (default: 50)
  --resolvers <file>       Custom DNS resolvers file
  --full                   Run all modules
  --ports                  Enable port scanning
  --nuclei                 Enable nuclei scanning
  --fuzz                   Enable directory fuzzing with dirsearch
  --no-probe               Skip HTTP probing
  --no-urls                Skip URL collection
  --help                   Show this help
  --version                Show version
EOF
}

# Tool installation instructions
declare -A TOOLS
TOOLS[subfinder]="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
TOOLS[assetfinder]="go install github.com/tomnomnom/assetfinder@latest"
TOOLS[amass]="go install github.com/owasp-amass/amass/v4/...@latest"
TOOLS[httpx]="go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
TOOLS[naabu]="go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
TOOLS[nuclei]="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
TOOLS[waybackurls]="go install github.com/tomnomnom/waybackurls@latest"
TOOLS[gau]="go install github.com/lc/gau/v2/cmd/gau@latest"
TOOLS[waymore]="pip install waymore"
TOOLS[dirsearch]="pip install dirsearch"

# Check tool
check_tool() {
    local tool=$1
    if ! command -v "$tool" &> /dev/null; then
        warn "$tool not found. Install with: ${TOOLS[$tool]}"
        return 1
    fi
    return 0
}

# Defaults
DOMAIN=""
OUTPUT_DIR=""
THREADS=50
RESOLVERS=""
DO_FULL=false
DO_PORTS=false
DO_NUCLEI=false
DO_FUZZ=false
DO_PROBE=true
DO_URLS=true

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain) DOMAIN="$2"; shift 2;;
        -o|--output) OUTPUT_DIR="$2"; shift 2;;
        -t|--threads) THREADS="$2"; shift 2;;
        --resolvers) RESOLVERS="$2"; shift 2;;
        --full) DO_FULL=true; DO_PORTS=true; DO_NUCLEI=true; DO_FUZZ=true; shift;;
        --ports) DO_PORTS=true; shift;;
        --nuclei) DO_NUCLEI=true; shift;;
        --fuzz) DO_FUZZ=true; shift;;
        --no-probe) DO_PROBE=false; shift;;
        --no-urls) DO_URLS=false; shift;;
        --help) show_help; exit 0;;
        --version) echo "$VERSION"; exit 0;;
        *) error "Unknown option: $1"; show_help; exit 1;;
    esac
done

# Validate
if [[ -z "$DOMAIN" ]]; then
    error "Domain is required. Use -d <domain>"
    show_help
    exit 1
fi

# Output dirs
OUTPUT_DIR="${OUTPUT_DIR:-$DOMAIN}"
ENUM_DIR="$OUTPUT_DIR/enum"
RAW_DIR="$ENUM_DIR/raw"
WEB_DIR="$OUTPUT_DIR/web"
URLS_DIR="$OUTPUT_DIR/urls"
FUZZ_DIR="$OUTPUT_DIR/fuzzing"
PORTS_DIR="$OUTPUT_DIR/ports"
NUCLEI_DIR="$OUTPUT_DIR/nuclei"
mkdir -p "$RAW_DIR" "$WEB_DIR" "$URLS_DIR" "$FUZZ_DIR" "$PORTS_DIR" "$NUCLEI_DIR"

info "Target: $DOMAIN"
info "Output: $OUTPUT_DIR"
info "Threads: $THREADS"
[[ -n "$RESOLVERS" && -f "$RESOLVERS" ]] && info "Using resolvers: $RESOLVERS"

# 1. Subdomains
info "[1/6] Subdomain enumeration"
if check_tool subfinder; then
    subfinder -d "$DOMAIN" -all -silent -o "$RAW_DIR/subfinder.txt"
fi
if check_tool assetfinder; then
    assetfinder --subs-only "$DOMAIN" > "$RAW_DIR/assetfinder.txt"
fi
if command -v curl &>/dev/null && command -v jq &>/dev/null; then
    info "Querying crt.sh..."
    curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sed 's/\*\.\?//g' | grep -i "\.$DOMAIN" | sort -u > "$RAW_DIR/crtsh.txt"
fi
if check_tool amass; then
    amass enum -passive -d "$DOMAIN" -o "$RAW_DIR/amass.txt"
fi

# Combine all subdomains
cat "$RAW_DIR"/*.txt 2>/dev/null | grep -i "\.$DOMAIN" | sort -u > "$ENUM_DIR/all_subdomains.txt"
SUBDOMAIN_COUNT=$(wc -l < "$ENUM_DIR/all_subdomains.txt" || echo 0)
success "Found $SUBDOMAIN_COUNT unique subdomains"

# 2. HTTP Probing
if [[ "$DO_PROBE" == true ]]; then
    info "[2/6] Probing hosts"
    if check_tool httpx; then
        httpx -l "$ENUM_DIR/all_subdomains.txt" -silent -status-code -title -tech-detect -content-length -o "$WEB_DIR/httpx_results.txt"
        awk '{print $1}' "$WEB_DIR/httpx_results.txt" | sort -u > "$WEB_DIR/alive_hosts.txt"
        ALIVE_COUNT=$(wc -l < "$WEB_DIR/alive_hosts.txt" || echo 0)
        success "Found $ALIVE_COUNT alive hosts"
    fi
else
    info "[2/6] Skipping HTTP probing"
fi

# 3. URL Collection
if [[ "$DO_URLS" == true ]]; then
    info "[3/6] URL collection"
    URL_TARGETS="$WEB_DIR/alive_hosts.txt"
    [[ ! -s "$URL_TARGETS" ]] && URL_TARGETS="$ENUM_DIR/all_subdomains.txt"

    if [[ -s "$URL_TARGETS" ]]; then
        if check_tool waybackurls; then
            cat "$URL_TARGETS" | waybackurls > "$URLS_DIR/waybackurls.txt"
        fi
        if check_tool gau; then
            cat "$URL_TARGETS" | gau > "$URLS_DIR/gau.txt"
        fi
        if check_tool waymore; then
            waymore -i "$URL_TARGETS" -mode U -oU "$URLS_DIR/waymore.txt"
        fi
        
        cat "$URLS_DIR"/*.txt 2>/dev/null | sort -u > "$URLS_DIR/all_urls.txt"
        URL_COUNT=$(wc -l < "$URLS_DIR/all_urls.txt" || echo 0)
        success "Collected $URL_COUNT unique URLs"
    else
        warn "No hosts found for URL collection"
    fi
else
    info "[3/6] Skipping URL collection"
fi

# 4. Directory Fuzzing
if [[ "$DO_FUZZ" == true ]]; then
    info "[4/6] Directory fuzzing"
    FUZZ_TARGETS="$WEB_DIR/alive_hosts.txt"
    if check_tool dirsearch && [[ -s "$FUZZ_TARGETS" ]]; then
        info "Running dirsearch on all alive hosts..."
        dirsearch -L "$FUZZ_TARGETS" --format=simple --output="$FUZZ_DIR/fuzz_results.txt" --include-status=200-299,301 --threads=50 --random-agent --quiet
        FUZZ_COUNT=$(grep -c -E " 2[0-9]{2}| 301" "$FUZZ_DIR/fuzz_results.txt" 2>/dev/null || echo 0)
        success "Found $FUZZ_COUNT interesting endpoints"
    else
        warn "dirsearch not found or no alive hosts to fuzz."
        FUZZ_COUNT=0
    fi
else
    info "[4/6] Skipping directory fuzzing"
    FUZZ_COUNT=0
fi

# 5. Port Scanning
if [[ "$DO_PORTS" == true ]]; then
    info "[5/6] Port scanning"
    PORT_TARGETS="$ENUM_DIR/all_subdomains.txt"
    if check_tool naabu; then
        naabu -l "$PORT_TARGETS" -silent -top-ports 1000 -rate 1000 -t "$THREADS" -o "$PORTS_DIR/open_ports.txt"
        PORT_COUNT=$(wc -l < "$PORTS_DIR/open_ports.txt" || echo 0)
        success "Found $PORT_COUNT open ports"
    else
        warn "naabu not found"
        PORT_COUNT=0
    fi
else
    info "[5/6] Skipping port scanning"
    PORT_COUNT=0
fi

# 6. Nuclei
if [[ "$DO_NUCLEI" == true ]]; then
    info "[6/6] Nuclei scanning"
    NUCLEI_TARGETS="$WEB_DIR/alive_hosts.txt"
    if check_tool nuclei && [[ -s "$NUCLEI_TARGETS" ]]; then
        nuclei -l "$NUCLEI_TARGETS" -o "$NUCLEI_DIR/vulnerabilities.txt"
        VULN_COUNT=$(wc -l < "$NUCLEI_DIR/vulnerabilities.txt" 2>/dev/null || echo 0)
        success "Found $VULN_COUNT potential vulnerabilities"
    else
        warn "nuclei not found or no alive hosts to scan."
        VULN_COUNT=0
    fi
else
    info "[6/6] Skipping nuclei scanning"
    VULN_COUNT=0
fi

# Summary
echo
success "Recon complete!"
info "Results saved in: $OUTPUT_DIR"
info "Subdomains: $SUBDOMAIN_COUNT found"
[[ "$DO_PROBE" == true ]] && info "Alive hosts: ${ALIVE_COUNT:-0}"
[[ "$DO_URLS" == true ]] && info "URLs: ${URL_COUNT:-0}"
[[ "$DO_FUZZ" == true ]] && info "Fuzzed endpoints: $FUZZ_COUNT"
[[ "$DO_PORTS" == true ]] && info "Open ports: $PORT_COUNT"
[[ "$DO_NUCLEI" == true ]] && info "Vulnerabilities: $VULN_COUNT"