#!/bin/bash

# SpiderCo - Advanced Reconnaissance Tool
# Author: Mohamed-Yasser-Ali
# Version: 2.1.0

set -euo pipefail

VERSION="2.1.0"

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
  --full                   Run all modules
  --ports                  Enable port scanning
  --nuclei                 Enable nuclei scanning
  --fuzz                   Enable directory fuzzing with dirsearch
  --no-probe              Skip HTTP probing
  --no-urls               Skip URL collection
  --help                  Show this help
  --version               Show version

Examples:
  $0 -d example.com
  $0 -d example.com --full --threads 100
  $0 -d example.com --fuzz --resolvers custom_resolvers.txt
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
DO_FUZZ=false
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
            DO_FUZZ=true
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
        --fuzz)
            DO_FUZZ=true
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
FUZZ_DIR="$OUTPUT_DIR/fuzzing"
PORTS_DIR="$OUTPUT_DIR/ports"
NUCLEI_DIR="$OUTPUT_DIR/nuclei"

mkdir -p "$RAW_DIR" "$WEB_DIR" "$URLS_DIR" "$FUZZ_DIR" "$PORTS_DIR" "$NUCLEI_DIR"

info "Target: $DOMAIN"
info "Output: $OUTPUT_DIR"
info "Threads: $THREADS"

if [[ -n "$RESOLVERS" && -f "$RESOLVERS" ]]; then
    info "Using resolvers: $RESOLVERS"
fi

# 1. Subdomain Enumeration
info "[1/7] Subdomain enumeration"

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
    | grep -iE "^[a-z0-9._-]+\.$DOMAIN$" \
    | grep -vE ' |note:|->|^[0-9.]+$|^[0-9a-f:]+$' \
    | sort -u > "$ENUM_DIR/all_subdomains.txt"

SUBDOMAIN_COUNT=$(wc -l < "$ENUM_DIR/all_subdomains.txt")
success "Found $SUBDOMAIN_COUNT unique subdomains"

# 2. DNS Resolution
info "[2/7] DNS resolution"

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
    info "[3/7] HTTP probing"
    
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
    info "[3/7] Skipping HTTP probing"
fi

# 4. URL Collection
if [[ "$DO_URLS" == true ]]; then
    info "[4/7] URL collection"
    
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
    
    # Waymore
    if check_tool waymore; then
        info "Collecting URLs with waymore..."
        waymore -i "$TARGET_FILE" -mode U -f "$URLS_DIR/waymore.txt" 2>/dev/null || true
    fi
    
    # Combine URLs
    cat "$URLS_DIR"/*.txt 2>/dev/null | sort -u > "$URLS_DIR/all_urls.txt" || true
    URL_COUNT=$(wc -l < "$URLS_DIR/all_urls.txt" 2>/dev/null || echo 0)
    success "Collected $URL_COUNT unique URLs"
else
    info "[4/7] Skipping URL collection"
fi

# 5. Directory Fuzzing
if [[ "$DO_FUZZ" == true ]]; then
    info "[5/7] Directory fuzzing"
    
    if check_tool dirsearch; then
        FUZZ_TARGET_FILE="$WEB_DIR/alive_hosts.txt"
        if [[ ! -s "$FUZZ_TARGET_FILE" ]]; then
            FUZZ_TARGET_FILE="$ENUM_DIR/resolved.txt"
        fi
        
        if [[ -s "$FUZZ_TARGET_FILE" ]]; then
            info "Fuzzing directories on discovered hosts..."
            while read -r host; do
                if [[ -n "$host" ]]; then
                    clean_host=$(echo "$host" | sed 's|https\?://||' | sed 's|/.*||')
                    if [[ "$host" =~ ^https?:// ]]; then
                        target_url="$host"
                    else
                        target_url="https://$host"
                    fi
                    info "Fuzzing $clean_host..."
                    dirsearch -u "$target_url" \
                             --format=simple \
                             --output="$FUZZ_DIR/${clean_host}.txt" \
                             --include-status=200,201,202,203,204,205,206,207,208,226,301 \
                             --threads=20 \
                             --timeout=10 \
                             --random-agent \
                             --quiet \
                             2>/dev/null || true
                    if [[ ! -s "$FUZZ_DIR/${clean_host}.txt" && ! "$host" =~ ^http:// ]]; then
                        info "Retrying $clean_host with HTTP..."
                        dirsearch -u "http://$host" \
                                 --format=simple \
                                 --output="$FUZZ_DIR/${clean_host}_http.txt" \
                                 --include-status=200,201,202,203,204,205,206,207,208,226,301 \
                                 --threads=20 \
                                 --timeout=10 \
                                 --random-agent \
                                 --quiet \
                                 2>/dev/null || true
                    fi
                fi
            done < "$FUZZ_TARGET_FILE"
            
            info "Processing fuzzing results..."
            for fuzz_file in "$FUZZ_DIR"/*.txt; do
                if [[ -f "$fuzz_file" && -s "$fuzz_file" ]]; then
                    filename=$(basename "$fuzz_file" .txt)
                    grep -E "([[:space:]]2[0-9]{2}|[[:space:]]301)" "$fuzz_file" | sort -u > "$FUZZ_DIR/filtered_${filename}.txt" 2>/dev/null || true
                fi
            done
            
            FUZZ_COUNT=$(find "$FUZZ_DIR" -name "filtered_*.txt" -exec cat {} \; 2>/dev/null | wc -l || echo 0)
            success "Found $FUZZ_COUNT interesting endpoints across all hosts"
        else
            warn "No hosts found for fuzzing"
            FUZZ_COUNT=0
        fi
    else
        warn "dirsearch not found, skipping directory fuzzing"
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
        PORT_COUNT=0
    fi
else
    info "[6/7] Skipping port scanning"
    PORT_COUNT=0
fi

# 7. Nuclei Scanning
if [[ "$DO_NUCLEI" == true ]]; then
    info "[7/7] Nuclei scanning"
    
    if check_tool nuclei; then
        TARGET_FILE="$WEB_DIR/alive_hosts.txt"
        if [[ ! -s "$TARGET_FILE" ]]; then
            TARGET_FILE="$ENUM_DIR/resolved.txt"
        fi
        
        info "Running nuclei scans..."
        nuclei -l "$TARGET_FILE" \
               -silent \
               > "$NUCLEI_DIR/vulnerabilities.txt" 2>/dev/null || true
        
        VULN_COUNT=$(wc -l < "$NUCLEI_DIR/vulnerabilities.txt" 2>/dev/null || echo 0)
        success "Found $VULN_COUNT potential vulnerabilities"
    else
        warn "nuclei not found, skipping vulnerability scanning"
        VULN_COUNT=0
    fi
else
    info "[7/7] Skipping nuclei scanning"
    VULN_COUNT=0
fi

# Summary
echo
success "Reconnaissance complete!"
info "Results saved in: $OUTPUT_DIR"
info "Subdomains: $SUBDOMAIN_COUNT found, $RESOLVED_COUNT resolved"
if [[ "$DO_PROBE" == true ]]; then
    info "Alive hosts: $ALIVE_COUNT"
fi
if [[ "$DO_URLS" == true ]]; then
    info "URLs: $URL_COUNT"
fi
if [[ "$DO_FUZZ" == true ]]; then
    info "Fuzzed endpoints: $FUZZ_COUNT"
fi
if [[ "$DO_PORTS" == true ]]; then
    info "Open ports: $PORT_COUNT"
fi
if [[ "$DO_NUCLEI" == true ]]; then
    info "Vulnerabilities: $VULN_COUNT"
fi
