#!/bin/bash

# SpiderCo - Advanced Reconnaissance Tool
# Author: Mohamed-Yasser-Ali
# Version: 2.0.0

set -euo pipefail

VERSION="2.0.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
success() { echo -e "${GREEN}[DONE]${NC} $1"; }

# Help function
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
  --full                   Run all modules (default: enum + resolve + probe)
  --ports                  Enable port scanning
  --nuclei                 Enable nuclei scanning
  --no-probe              Skip HTTP probing
  --no-urls               Skip URL collection
  --help                  Show this help
  --version               Show version

Examples:
  $0 -d example.com
  $0 -d example.com --full --threads 100
  $0 -d example.com --resolvers custom_resolvers.txt
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

# Check if tool exists
check_tool() {
    local tool=$1
    if ! command -v "$tool" &> /dev/null; then
        warn "$tool not found. Install with: ${TOOLS[$tool]}"
        return 1
    fi
    return 0
}

# Default values
DOMAIN=""
OUTPUT_DIR=""
THREADS=50
RESOLVERS=""
DO_FULL=false
DO_PORTS=false
DO_NUCLEI=false
DO_PROBE=true
DO_URLS=true

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -t|--threads)
            THREADS="$2"
            shift 2
            ;;
        --resolvers)
            RESOLVERS="$2"
            shift 2
            ;;
        --full)
            DO_FULL=true
            DO_PORTS=true
            DO_NUCLEI=true
            shift
            ;;
        --ports)
            DO_PORTS=true
            shift
            ;;
        --nuclei)
            DO_NUCLEI=true
            shift
            ;;
        --no-probe)
            DO_PROBE=false
            shift
            ;;
        --no-urls)
            DO_URLS=false
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        --version)
            echo "$VERSION"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Validate required arguments
if [[ -z "$DOMAIN" ]]; then
    error "Domain is required. Use -d <domain>"
    show_help
    exit 1
fi

# Set output directory
if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="$DOMAIN"
fi

# Create directories
ENUM_DIR="$OUTPUT_DIR/enum"
RAW_DIR="$ENUM_DIR/raw"
WEB_DIR="$OUTPUT_DIR/web"
URLS_DIR="$OUTPUT_DIR/urls"
PORTS_DIR="$OUTPUT_DIR/ports"
NUCLEI_DIR="$OUTPUT_DIR/nuclei"

mkdir -p "$RAW_DIR" "$WEB_DIR" "$URLS_DIR" "$PORTS_DIR" "$NUCLEI_DIR"

info "Target: $DOMAIN"
info "Output: $OUTPUT_DIR"
info "Threads: $THREADS"

if [[ -n "$RESOLVERS" && -f "$RESOLVERS" ]]; then
    info "Using resolvers: $RESOLVERS"
fi

# 1. Subdomain Enumeration
info "[1/6] Subdomain enumeration"

# Subfinder
if check_tool subfinder; then
    info "Running subfinder..."
    subfinder_cmd="subfinder -d $DOMAIN -all -silent"
    if [[ -n "$RESOLVERS" && -f "$RESOLVERS" ]]; then
        subfinder_cmd="$subfinder_cmd -rL $RESOLVERS"
    fi
    $subfinder_cmd > "$RAW_DIR/subfinder.txt" 2>/dev/null || true
fi

# Assetfinder
if check_tool assetfinder; then
    info "Running assetfinder..."
    assetfinder --subs-only "$DOMAIN" > "$RAW_DIR/assetfinder.txt" 2>/dev/null || true
fi

# crt.sh
if command -v curl &> /dev/null && command -v jq &> /dev/null; then
    info "Querying crt.sh..."
    curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null \
        | jq -r '.[].name_value' 2>/dev/null \
        | sed 's/\*\.//g' \
        | grep -E "\.$DOMAIN$" \
        | sort -u > "$RAW_DIR/crtsh.txt" || true
fi

# Amass
if check_tool amass; then
    info "Running amass..."
    amass enum -passive -d "$DOMAIN" -o "$RAW_DIR/amass.txt" 2>/dev/null || true
fi

# Combine and clean results
info "Combining subdomain results..."
cat "$RAW_DIR"/*.txt 2>/dev/null \
    | grep -E "\.$DOMAIN$" \
    | grep -v ' ' \
    | sort -u > "$ENUM_DIR/all_subdomains.txt"

SUBDOMAIN_COUNT=$(wc -l < "$ENUM_DIR/all_subdomains.txt")
success "Found $SUBDOMAIN_COUNT unique subdomains"

# 2. DNS Resolution
info "[2/6] DNS resolution"

if check_tool dnsx; then
    info "Resolving subdomains with dnsx..."
    dnsx -l "$ENUM_DIR/all_subdomains.txt" -silent > "$ENUM_DIR/resolved.txt" 2>/dev/null || true
else
    warn "dnsx not found, using basic resolution"
    while read -r subdomain; do
        if host "$subdomain" &>/dev/null; then
            echo "$subdomain"
        fi
    done < "$ENUM_DIR/all_subdomains.txt" > "$ENUM_DIR/resolved.txt"
fi

RESOLVED_COUNT=$(wc -l < "$ENUM_DIR/resolved.txt")
success "Resolved $RESOLVED_COUNT subdomains"

# 3. HTTP Probing
if [[ "$DO_PROBE" == true ]]; then
    info "[3/6] HTTP probing"
    
    if check_tool httpx; then
        info "Probing with httpx..."
        httpx -l "$ENUM_DIR/resolved.txt" \
              -silent \
              -status-code \
              -title \
              -tech-detect \
              -content-length \
              > "$WEB_DIR/httpx_results.txt" 2>/dev/null || true
        
        # Extract alive hosts
        awk '{print $1}' "$WEB_DIR/httpx_results.txt" \
            | sort -u > "$WEB_DIR/alive_hosts.txt"
        
        ALIVE_COUNT=$(wc -l < "$WEB_DIR/alive_hosts.txt")
        success "Found $ALIVE_COUNT alive hosts"
    else
        warn "httpx not found, skipping HTTP probing"
    fi
else
    info "[3/6] Skipping HTTP probing"
fi

# 4. URL Collection
if [[ "$DO_URLS" == true ]]; then
    info "[4/6] URL collection"
    
    TARGET_FILE="$WEB_DIR/alive_hosts.txt"
    if [[ ! -s "$TARGET_FILE" ]]; then
        TARGET_FILE="$ENUM_DIR/resolved.txt"
    fi
    
    # Waybackurls
    if check_tool waybackurls; then
        info "Collecting URLs with waybackurls..."
        cat "$TARGET_FILE" | waybackurls > "$URLS_DIR/waybackurls.txt" 2>/dev/null || true
    fi
    
    # GAU
    if check_tool gau; then
        info "Collecting URLs with gau..."
        gau "$DOMAIN" > "$URLS_DIR/gau.txt" 2>/dev/null || true
    fi
    
    # Combine URLs
    cat "$URLS_DIR"/*.txt 2>/dev/null | sort -u > "$URLS_DIR/all_urls.txt" || true
    URL_COUNT=$(wc -l < "$URLS_DIR/all_urls.txt" 2>/dev/null || echo 0)
    success "Collected $URL_COUNT unique URLs"
else
    info "[4/6] Skipping URL collection"
fi

# 5. Port Scanning
if [[ "$DO_PORTS" == true ]]; then
    info "[5/6] Port scanning"
    
    if check_tool naabu; then
        info "Scanning ports with naabu..."
        naabu -l "$ENUM_DIR/resolved.txt" \
              -silent \
              -top-ports 1000 \
              -rate 1000 \
              > "$PORTS_DIR/open_ports.txt" 2>/dev/null || true
        
        PORT_COUNT=$(wc -l < "$PORTS_DIR/open_ports.txt" 2>/dev/null || echo 0)
        success "Found $PORT_COUNT open ports"
    else
        warn "naabu not found, skipping port scanning"
    fi
else
    info "[5/6] Skipping port scanning"
fi

# 6. Nuclei Scanning
if [[ "$DO_NUCLEI" == true ]]; then
    info "[6/6] Nuclei scanning"
    
    if check_tool nuclei; then
        TARGET_FILE="$WEB_DIR/alive_hosts.txt"
        if [[ ! -s "$TARGET_FILE" ]]; then
            TARGET_FILE="$ENUM_DIR/resolved.txt"
        fi
        
        info "Running nuclei scans..."
        nuclei -l "$TARGET_FILE" \
               -silent \
               > "$NUCLEI_DIR/vulnerabilities.txt" 2>/dev/null || true
        
        VULN_COUNT=$(wc -l < "$NUCLEI_DIR/vulnerabilities.txt" 2
