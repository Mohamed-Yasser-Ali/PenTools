#!/bin/bash

# SpiderCo - Advanced Reconnaissance Tool
# Author: Mohamed-Yasser-Ali
# Version: 2.2.0 (cleaned)

set -euo pipefail

VERSION="2.2.0"

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
TOOLS[dnsx]="go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
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
info "[1/7] Subdomain enumeration"
check_tool subfinder && subfinder -d "$DOMAIN" -all -silent ${RESOLVERS:+-rL $RESOLVERS} > "$RAW_DIR/subfinder.txt" || true
check_tool assetfinder && assetfinder --subs-only "$DOMAIN" > "$RAW_DIR/assetfinder.txt" || true
(command -v curl &>/dev/null && command -v jq &>/dev/null) && curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sed 's/\\*\\.//g' | grep -i "\\.${DOMAIN}" | sort -u > "$RAW_DIR/crtsh.txt" || true
check_tool amass && amass enum -passive -d "$DOMAIN" -o "$RAW_DIR/amass.txt" || true

cat "$RAW_DIR"/*.txt 2>/dev/null | grep -iE "^[a-z0-9.-]+\\.$DOMAIN$" | sort -u > "$ENUM_DIR/all_subdomains.txt"
SUBDOMAIN_COUNT=$(wc -l < "$ENUM_DIR/all_subdomains.txt")
success "Found $SUBDOMAIN_COUNT unique subdomains"

# 2. DNS Resolution
info "[2/7] DNS resolution"
if check_tool dnsx; then
    dnsx -l "$ENUM_DIR/all_subdomains.txt" -silent -t "$THREADS" > "$ENUM_DIR/resolved.txt" || true
else
    while read -r s; do host "$s" &>/dev/null && echo "$s"; done < "$ENUM_DIR/all_subdomains.txt" > "$ENUM_DIR/resolved.txt"
fi
RESOLVED_COUNT=$(wc -l < "$ENUM_DIR/resolved.txt")
success "Resolved $RESOLVED_COUNT subdomains"
NEXT_TARGET_FILE="$ENUM_DIR/resolved.txt"

# 3. HTTP Probing
if [[ "$DO_PROBE" == true ]]; then
    info "[3/7] HTTP probing"
    if check_tool httpx; then
        httpx -l "$NEXT_TARGET_FILE" -silent -status-code -title -tech-detect -content-length -t "$THREADS" > "$WEB_DIR/httpx_results.txt" || true
        awk '{print $1}' "$WEB_DIR/httpx_results.txt" | sort -u > "$WEB_DIR/alive_hosts.txt"
        ALIVE_COUNT=$(wc -l < "$WEB_DIR/alive_hosts.txt")
        success "Found $ALIVE_COUNT alive hosts"
    fi
else
    info "[3/7] Skipping HTTP probing"
fi

# 4. URL Collection
if [[ "$DO_URLS" == true ]]; then
    info "[4/7] URL collection"
    if [[ -s "$WEB_DIR/alive_hosts.txt" || -s "$ENUM_DIR/resolved.txt" ]]; then
        check_tool waybackurls && cat "$NEXT_TARGET_FILE" | waybackurls > "$URLS_DIR/waybackurls.txt" || true
        check_tool gau && gau "$DOMAIN" > "$URLS_DIR/gau.txt" || true
        check_tool waymore && waymore -i "$NEXT_TARGET_FILE" -mode U -f "$URLS_DIR/waymore.txt" || true
        cat "$URLS_DIR"/*.txt 2>/dev/null | sort -u > "$URLS_DIR/all_urls.txt"
        URL_COUNT=$(wc -l < "$URLS_DIR/all_urls.txt" 2>/dev/null || echo 0)
        success "Collected $URL_COUNT unique URLs"
    else
        warn "No hosts found for URL collection"
    fi
else
    info "[4/7] Skipping URL collection"
fi

# 5. Directory Fuzzing
if [[ "$DO_FUZZ" == true ]]; then
    info "[5/7] Directory fuzzing"
    if check_tool dirsearch && [[ -s "$NEXT_TARGET_FILE" ]]; then
        while read -r host; do
            [[ -z "$host" ]] && continue
            clean_host=$(echo "$host" | sed 's|https\?://||;s|/.*||')
            target_url=$([[ "$host" =~ ^https?:// ]] && echo "$host" || echo "https://$host")
            dirsearch -u "$target_url" --format=simple --output="$FUZZ_DIR/${clean_host}.txt" --include-status=200-299,301 --threads=20 --timeout=10 --random-agent --quiet || true
            [[ ! -s "$FUZZ_DIR/${clean_host}.txt" && ! "$host" =~ ^http:// ]] && dirsearch -u "http://$host" --format=simple --output="$FUZZ_DIR/${clean_host}_http.txt" --include-status=200-299,301 --threads=20 --timeout=10 --random-agent --quiet || true
        done < "$NEXT_TARGET_FILE"
        FUZZ_COUNT=$(grep -Eh " 2[0-9]{2}| 301" "$FUZZ_DIR"/*.txt 2>/dev/null | wc -l || echo 0)
        success "Found $FUZZ_COUNT interesting endpoints"
    else
        warn "No hosts found for fuzzing"
        FUZZ_COUNT=0
    fi
else
    info "[5/7] Skipping directory fuzzing"
    FUZZ_COUNT=0
fi

# 6. Port Scanning
if [[ "$DO_PORTS" == true ]]; then
    info "[6/7] Port scanning"
    if check_tool naabu; then
        naabu -l "$NEXT_TARGET_FILE" -silent -top-ports 1000 -rate 1000 -t "$THREADS" > "$PORTS_DIR/open_ports.txt" || true
        PORT_COUNT=$(wc -l < "$PORTS_DIR/open_ports.txt" 2>/dev/null || echo 0)
        success "Found $PORT_COUNT open ports"
    else
        warn "naabu not found"
        PORT_COUNT=0
    fi
else
    info "[6/7] Skipping port scanning"
    PORT_COUNT=0
fi

# 7. Nuclei
if [[ "$DO_NUCLEI" == true ]]; then
    info "[7/7] Nuclei scanning"
    if check_tool nuclei; then
        TARGET_FILE="$WEB_DIR/alive_hosts.txt"
        [[ ! -s "$TARGET_FILE" ]] && TARGET_FILE="$NEXT_TARGET_FILE"
        nuclei -l "$TARGET_FILE" -severity low,medium,high,critical -silent -t "$THREADS" > "$NUCLEI_DIR/vulnerabilities.txt" || true
        VULN_COUNT=$(wc -l < "$NUCLEI_DIR/vulnerabilities.txt" 2>/dev/null || echo 0)
        success "Found $VULN_COUNT potential vulnerabilities"
    else
        warn "nuclei not found"
        VULN_COUNT=0
    fi
else
    info "[7/7] Skipping nuclei scanning"
    VULN_COUNT=0
fi

# Summary
echo
success "Recon complete!"
info "Results saved in: $OUTPUT_DIR"
info "Subdomains: $SUBDOMAIN_COUNT found, $RESOLVED_COUNT resolved"
[[ "$DO_PROBE" == true ]] && info "Alive hosts: ${ALIVE_COUNT:-0}"
[[ "$DO_URLS" == true ]] && info "URLs: ${URL_COUNT:-0}"
[[ "$DO_FUZZ" == true ]] && info "Fuzzed endpoints: $FUZZ_COUNT"
[[ "$DO_PORTS" == true ]] && info "Open ports: $PORT_COUNT"
[[ "$DO_NUCLEI" == true ]] && info "Vulnerabilities: $VULN_COUNT"
