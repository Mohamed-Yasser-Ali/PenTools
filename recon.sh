#!/bin/bash

# Advanced recon script for bug bounty hunting
# Author: Mohamed-Yasser-Ali (automated assistant enhancement)
#
# Core workflow (all modular & optional):
#   1. Subdomain enumeration (passive + optional brute) (subfinder/assetfinder/amass/shuffledns)
#   2. Resolution (dnsx) & filtering
#   3. Probing (httpx) with tech detection & metadata
#   4. URL archive collection (waybackurls, gau, waymore) / optional crawling (katana)
#   5. Optional port scan (naabu)
#   6. Optional nuclei scan
#
# Quick usage:
#   ./recon.sh -d target.com -a            # run with sane defaults (enum + probe + urls)
#   ./recon.sh -d target.com --full        # run everything (enum+probe+urls+ports+nuclei)
#
# Flags:
#   -d, --domain <domain>       Target apex domain (required)
#   -o, --outdir <dir>          Output directory (default: recon-<domain>)
#   -t, --threads <n>           Threads/concurrency (default: 50)
#       --resolvers <file>      Custom resolvers file (used by subfinder/dnsx/etc if present)
#       --no-urls               Skip URL archive collection
#       --no-probe              Skip HTTP probing
#       --ports                 Run port scan (naabu if installed)
#       --nuclei                Run nuclei on probed hosts
#       --full                  Enable all optional modules (URLs + port scan + nuclei)
#       --keep-temp             Keep intermediate temp files
#       --help                  Show help
#
# Output tree (example):
#   outdir/
#     enum/raw/*.txt            Raw tool outputs
#     enum/all_subdomains.txt   Collated uniques
#     enum/resolved.txt         DNS-resolved (dnsx)
#     web/httpx_full.txt        Detailed httpx output
#     web/alive_hosts.txt       Alive web hosts (scheme://host)
#     urls/*.txt                Collected URLs
#     scans/ports.txt           Open ports (if run)
#     scans/nuclei.txt          Nuclei findings (if run)

set -Eeuo pipefail
IFS=$'\n\t'

VERSION="1.3.1"

COLOR_RED="\033[31m"; COLOR_GREEN="\033[32m"; COLOR_YELLOW="\033[33m"; COLOR_BLUE="\033[34m"; COLOR_RESET="\033[0m"

log() { printf "%b[%s]%b %s\n" "$COLOR_BLUE" "INFO" "$COLOR_RESET" "$1"; }
warn() { printf "%b[%s]%b %s\n" "$COLOR_YELLOW" "WARN" "$COLOR_RESET" "$1"; }
err()  { printf "%b[%s]%b %s\n" "$COLOR_RED" "ERR" "$COLOR_RESET" "$1"; }
succ() { printf "%b[%s]%b %s\n" "$COLOR_GREEN" "DONE" "$COLOR_RESET" "$1"; }

has_flag(){
	# Usage: has_flag <tool> <flag>
	local tool="$1" flag="$2"
	command -v "$tool" >/dev/null 2>&1 || return 1
	"$tool" -h 2>&1 | grep -qw -- "$flag"
}

show_help(){ sed -n '1,/^set -Eeuo/p' "$0" | sed 's/^# \{0,1\}//' | sed '/^$/q'; }

need_tool(){
	local name="$1" install="$2"; shift 2 || true
	if ! command -v "$name" &>/dev/null; then
		warn "$name not installed. Install: $install"
		return 1
	fi
	return 0
}

# Catalog of optional tools & suggested install commands
declare -A INSTALL
INSTALL[subfinder]="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
INSTALL[assetfinder]="go install github.com/tomnomnom/assetfinder@latest"
INSTALL[amass]="snap install amass || go install github.com/owasp-amass/amass/v4/...@latest"
INSTALL[dnsx]="go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
INSTALL[shuffledns]="go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
INSTALL[naabu]="go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
INSTALL[httpx]="go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
INSTALL[waymore]="pip install waymore"
INSTALL[waybackurls]="go install github.com/tomnomnom/waybackurls@latest"
INSTALL[gau]="go install github.com/lc/gau/v2/cmd/gau@latest"
INSTALL[katana]="go install github.com/projectdiscovery/katana/cmd/katana@latest"
INSTALL[nuclei]="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
INSTALL[curl]="(preinstalled on most systems)"
INSTALL[jq]="sudo apt install -y jq || brew install jq || choco install jq"

DOMAIN=""; OUTDIR=""; THREADS=50; RESOLVERS=""; DO_URLS=1; DO_PROBE=1; DO_PORTS=0; DO_NUCLEI=0; KEEP_TEMP=0

if [ $# -eq 0 ]; then show_help; exit 1; fi

while [ $# -gt 0 ]; do
	case "$1" in
		-d|--domain) DOMAIN="$2"; shift 2;;
		-o|--outdir) OUTDIR="$2"; shift 2;;
		-t|--threads) THREADS="$2"; shift 2;;
		--resolvers) RESOLVERS="$2"; shift 2;;
		--no-urls) DO_URLS=0; shift;;
		--no-probe) DO_PROBE=0; shift;;
		--ports) DO_PORTS=1; shift;;
		--nuclei) DO_NUCLEI=1; shift;;
		--full) DO_URLS=1; DO_PROBE=1; DO_PORTS=1; DO_NUCLEI=1; shift;;
		--keep-temp) KEEP_TEMP=1; shift;;
		--help|-h) show_help; exit 0;;
		--version) echo "$VERSION"; exit 0;;
		*) err "Unknown option: $1"; show_help; exit 1;;
	esac
done

if [ -z "$DOMAIN" ]; then err "Domain is required (-d)."; exit 1; fi
if [ -z "$OUTDIR" ]; then OUTDIR="$DOMAIN"; fi

RAW_DIR="$OUTDIR/enum/raw"
WEB_DIR="$OUTDIR/web"
URL_DIR="$OUTDIR/urls"
SCAN_DIR="$OUTDIR/scans"
mkdir -p "$RAW_DIR" "$WEB_DIR" "$URL_DIR" "$SCAN_DIR"

log "Target: $DOMAIN"
log "Output: $OUTDIR" 

RESOLVER_ARG=""
if [ -n "$RESOLVERS" ] && [ -f "$RESOLVERS" ]; then
	# We'll decide the actual flag inside resolve_subdomains after detecting dnsx capabilities
	RESOLVER_ARG="$RESOLVERS"
	log "Using custom resolvers file: $RESOLVERS"
fi

enum_subdomains(){
	log "[1/6] Subdomain enumeration"
	(need_tool subfinder "${INSTALL[subfinder]}" && subfinder -d "$DOMAIN" -all -silent $RESOLVER_ARG -t "$THREADS" || true) > "$RAW_DIR/subfinder.txt" 2>/dev/null || true
		(need_tool assetfinder "${INSTALL[assetfinder]}" && assetfinder --subs-only "$DOMAIN" || true) > "$RAW_DIR/assetfinder.txt" 2>/dev/null || true
		# crt.sh certificate transparency enumeration
		if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
			log "Querying crt.sh"
			(
				curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" \
				| jq -r '.[].name_value' 2>/dev/null \
				| tr '\r' '\n' | tr ' ' '\n' | tr ',' '\n' \
				| sed 's/\\*\\.//g' | sed 's/^\.//' \
				| grep -iE "\\.$DOMAIN$" | sort -u
			) > "$RAW_DIR/crtsh.txt" || true
		else
			warn "Skipping crt.sh (missing curl or jq)"
			: > "$RAW_DIR/crtsh.txt"
		fi
	if need_tool amass "${INSTALL[amass]}"; then amass enum -passive -d "$DOMAIN" 2>/dev/null | tee "$RAW_DIR/amass.txt" >/dev/null; fi
	if need_tool shuffledns "${INSTALL[shuffledns]}" && [ -n "$RESOLVERS" ]; then
		 warn "Running shuffledns with resolvers (wordlist required for brute). Skipping if no wordlist env WORDLIST."
		 if [ -n "${WORDLIST:-}" ] && [ -f "$WORDLIST" ]; then
				shuffledns -d "$DOMAIN" -w "$WORDLIST" -r "$RESOLVERS" -mode bruteforce -t "$THREADS" 2>/dev/null | tee "$RAW_DIR/shuffledns.txt" >/dev/null || true
		 fi
	fi
		# Allow user to supply additional enumeration commands via CUSTOM_ENUM_CMDS (semicolon separated)
		if [ -n "${CUSTOM_ENUM_CMDS:-}" ]; then
			IFS=';' read -r -a EXTRA_CMDS <<< "$CUSTOM_ENUM_CMDS"
			for cmd in "${EXTRA_CMDS[@]}"; do
				log "Running custom enum: $cmd"
				bash -c "$cmd" 2>/dev/null | tee -a "$RAW_DIR/custom_enum.txt" >/dev/null || true
			done
		fi
	# Only include valid subdomains (exclude lines with spaces, notes, IPs, or records)
	cat "$RAW_DIR"/*.txt 2>/dev/null \
		| grep -iE "^[a-z0-9._-]+\\.$DOMAIN$" \
		| grep -vE ' |note:|->|^[0-9.]+$|^[0-9a-f:]+$' \
		| sort -u > "$OUTDIR/enum/all_subdomains.txt"
	local count=$(wc -l < "$OUTDIR/enum/all_subdomains.txt" || echo 0)
	succ "Collected $count unique subdomains"
}

resolve_subdomains(){
	log "[2/6] DNS resolution"
	if need_tool dnsx "${INSTALL[dnsx]}"; then
		DNSX_FLAGS=""
		# Add flags only if supported
		has_flag dnsx -silent && DNSX_FLAGS+=" -silent"
		if has_flag dnsx -t; then
			DNSX_FLAGS+=" -t $THREADS"
		elif has_flag dnsx -threads; then
			DNSX_FLAGS+=" -threads $THREADS"
		fi
		has_flag dnsx -retries && DNSX_FLAGS+=" -retries 2"
		# Resolver flag selection
		RESOLVER_FLAG=""
		if [ -n "$RESOLVER_ARG" ]; then
			if has_flag dnsx -r; then
				RESOLVER_FLAG=" -r $RESOLVER_ARG"
			elif has_flag dnsx -resolver; then
				RESOLVER_FLAG=" -resolver $RESOLVER_ARG"
			elif has_flag dnsx -resolvers; then
				RESOLVER_FLAG=" -resolvers $RESOLVER_ARG"
			else
				warn "dnsx does not support resolver flag on this version; continuing without custom resolvers"
			fi
		fi
		# First attempt with detected flags
		if ! dnsx $DNSX_FLAGS -l "$OUTDIR/enum/all_subdomains.txt" $RESOLVER_FLAG -o "$OUTDIR/enum/resolved.txt" 2>/dev/null; then
			warn "dnsx attempt with flags failed; trying minimal invocation"
			if ! dnsx -l "$OUTDIR/enum/all_subdomains.txt" -o "$OUTDIR/enum/resolved.txt" 2>/dev/null; then
				warn "dnsx minimal invocation failed"
			fi
		fi
	fi
	if [ ! -s "$OUTDIR/enum/resolved.txt" ]; then
		warn "Using fallback resolver loop (slower)"
		while read -r sub; do
			if command -v host >/dev/null 2>&1; then
				if host "$sub" >/dev/null 2>&1; then echo "$sub"; fi
			elif command -v dig >/dev/null 2>&1; then
				if dig +short "$sub" | grep -qE '^[0-9]'; then echo "$sub"; fi
			fi
		done < "$OUTDIR/enum/all_subdomains.txt" > "$OUTDIR/enum/resolved.txt" 2>/dev/null || true
	fi
	local count=$(wc -l < "$OUTDIR/enum/resolved.txt" || echo 0)
	succ "Resolved $count subdomains"
}

probe_http(){
	[ $DO_PROBE -eq 1 ] || { warn "Skipping HTTP probing"; return; }
	log "[3/6] HTTP probing"
	if need_tool httpx "${INSTALL[httpx]}"; then
		HTTPX_FLAGS=""
		has_flag httpx -silent && HTTPX_FLAGS+=" -silent"
		if has_flag httpx -threads; then
			HTTPX_FLAGS+=" -threads $THREADS"
		elif has_flag httpx -t; then
			HTTPX_FLAGS+=" -t $THREADS"
		fi
		for f in -follow-redirects -status-code -title -tech-detect -ip -websocket -cdn -content-length; do
			has_flag httpx "$f" && HTTPX_FLAGS+=" $f"
		done
		if has_flag httpx -rl; then
			HTTPX_FLAGS+=" -rl 100"
		elif has_flag httpx -rate; then
			HTTPX_FLAGS+=" -rate 100"
		fi
		if ! httpx -l "$OUTDIR/enum/resolved.txt" $HTTPX_FLAGS -o "$WEB_DIR/httpx_full.txt" 2>/dev/null; then
			warn "httpx attempt with detected flags failed; trying minimal run"
			httpx -l "$OUTDIR/enum/resolved.txt" -o "$WEB_DIR/httpx_full.txt" 2>/dev/null || true
		fi
		awk '{print $1}' "$WEB_DIR/httpx_full.txt" | sort -u > "$WEB_DIR/alive_hosts.txt" || true
		if [ ! -s "$WEB_DIR/alive_hosts.txt" ]; then
			warn "No alive hosts detected (possible network block or unsupported flags)"
		fi
		succ "HTTP alive hosts: $(wc -l < "$WEB_DIR/alive_hosts.txt" 2>/dev/null || echo 0)"
	else
		warn "httpx not installed; skipping probing"
	fi
}

collect_urls(){
	[ $DO_URLS -eq 1 ] || { warn "Skipping URL collection"; return; }
	log "[4/6] URL archive collection"
	local hostlist="$WEB_DIR/alive_hosts.txt"
	if [ ! -s "$hostlist" ]; then
		 warn "No alive hosts list found; using resolved subdomains"
		 hostlist="$OUTDIR/enum/resolved.txt"
	fi
	if need_tool waybackurls "${INSTALL[waybackurls]}"; then
		 cat "$hostlist" | waybackurls | sort -u > "$URL_DIR/waybackurls.txt" 2>/dev/null || true
	fi
	if need_tool gau "${INSTALL[gau]}"; then
		 gau --threads "$THREADS" --providers wayback,otx,commoncrawl,github -o "$URL_DIR/gau.txt" "$DOMAIN" 2>/dev/null || true
	fi
	if need_tool waymore "${INSTALL[waymore]}"; then
		 waymore -i "$hostlist" -o "$URL_DIR/waymore" -mode U 2>/dev/null || true
	fi
	if need_tool katana "${INSTALL[katana]}"; then
		 katana -list "$hostlist" -silent -aff -d 2 -jc -fx -o "$URL_DIR/katana.txt" 2>/dev/null || true
	fi
	cat "$URL_DIR"/*.txt 2>/dev/null | sort -u > "$URL_DIR/all_urls.txt" || true
	succ "Collected $(wc -l < "$URL_DIR/all_urls.txt" 2>/dev/null || echo 0) unique URLs"
}

port_scan(){
	[ $DO_PORTS -eq 1 ] || { warn "Skipping port scan"; return; }
	log "[5/6] Port scanning"
	if need_tool naabu "${INSTALL[naabu]}"; then
		 naabu -silent -top-ports 1000 -rate 1000 -list "$OUTDIR/enum/resolved.txt" -o "$SCAN_DIR/ports.txt" 2>/dev/null || true
		 succ "Ports results saved: $SCAN_DIR/ports.txt"
	else
		 warn "naabu not installed; skipping ports"
	fi
}

nuclei_scan(){
	[ $DO_NUCLEI -eq 1 ] || { warn "Skipping nuclei scan"; return; }
	log "[6/6] Nuclei scan"
	if need_tool nuclei "${INSTALL[nuclei]}"; then
		 local targets="$WEB_DIR/alive_hosts.txt"
		 [ -s "$targets" ] || targets="$OUTDIR/enum/resolved.txt"
		 nuclei -l "$targets" -silent -o "$SCAN_DIR/nuclei.txt" 2>/dev/null || true
		 succ "Nuclei findings stored: $SCAN_DIR/nuclei.txt"
	else
		 warn "nuclei not installed; skipping"
	fi
}

cleanup(){
	[ $KEEP_TEMP -eq 1 ] || rm -f "$OUTDIR"/enum/raw/*.tmp 2>/dev/null || true
}

enum_subdomains
resolve_subdomains
probe_http
collect_urls
port_scan
nuclei_scan
cleanup

log "Recon complete -> $OUTDIR"; succ "Done"
