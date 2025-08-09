package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// FULL embedded recon.sh content (version 1.3.1) for standalone usage.
// When updating recon.sh, re-run go install after bumping this constant.
// NOTE: Keeping everything verbatim allows identical behavior without local file.
const embeddedScript = `#!/bin/bash
` +
`# (Embedded by spiderco) If a local recon.sh exists, it will be preferred.
` +
`set -Eeuo pipefail
IFS=$'\n\t'
` +
`# === BEGIN ORIGINAL SCRIPT ===
` +
`VERSION="1.3.1"
` +
`COLOR_RED="\033[31m"; COLOR_GREEN="\033[32m"; COLOR_YELLOW="\033[33m"; COLOR_BLUE="\033[34m"; COLOR_RESET="\033[0m"
log() { printf "%b[%s]%b %s\n" "$COLOR_BLUE" "INFO" "$COLOR_RESET" "$1"; }
warn() { printf "%b[%s]%b %s\n" "$COLOR_YELLOW" "WARN" "$COLOR_RESET" "$1"; }
err()  { printf "%b[%s]%b %s\n" "$COLOR_RED" "ERR" "$COLOR_RESET" "$1"; }
succ() { printf "%b[%s]%b %s\n" "$COLOR_GREEN" "DONE" "$COLOR_RESET" "$1"; }
has_flag(){ local tool="$1" flag="$2"; command -v "$tool" >/dev/null 2>&1 || return 1; "$tool" -h 2>&1 | grep -qw -- "$flag"; }
show_help(){ sed -n '1,/^set -Eeuo/p' "$0" | sed 's/^# \{0,1\}//' | sed '/^$/q'; }
need_tool(){ local name="$1" install="$2"; shift 2 || true; if ! command -v "$name" &>/dev/null; then warn "$name not installed. Install: $install"; return 1; fi; return 0; }
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
if [ $# -eq 0 ]; then echo "Usage: $0 -d <domain> [--full]"; exit 1; fi
while [ $# -gt 0 ]; do case "$1" in -d|--domain) DOMAIN="$2"; shift 2;; -o|--outdir) OUTDIR="$2"; shift 2;; -t|--threads) THREADS="$2"; shift 2;; --resolvers) RESOLVERS="$2"; shift 2;; --no-urls) DO_URLS=0; shift;; --no-probe) DO_PROBE=0; shift;; --ports) DO_PORTS=1; shift;; --nuclei) DO_NUCLEI=1; shift;; --full) DO_URLS=1; DO_PROBE=1; DO_PORTS=1; DO_NUCLEI=1; shift;; --keep-temp) KEEP_TEMP=1; shift;; --version) echo "$VERSION"; exit 0;; *) shift;; esac; done
if [ -z "$DOMAIN" ]; then err "Domain required"; exit 1; fi
if [ -z "$OUTDIR" ]; then OUTDIR="$DOMAIN"; fi
RAW_DIR="$OUTDIR/enum/raw"; WEB_DIR="$OUTDIR/web"; URL_DIR="$OUTDIR/urls"; SCAN_DIR="$OUTDIR/scans"; mkdir -p "$RAW_DIR" "$WEB_DIR" "$URL_DIR" "$SCAN_DIR"
log "Target: $DOMAIN"; log "Output: $OUTDIR"
RESOLVER_ARG=""; if [ -n "$RESOLVERS" ] && [ -f "$RESOLVERS" ]; then RESOLVER_ARG="$RESOLVERS"; log "Using custom resolvers file: $RESOLVERS"; fi
enum_subdomains(){ log "[1/6] Subdomain enumeration"; (need_tool subfinder "${INSTALL[subfinder]}" && subfinder -d "$DOMAIN" -all -silent $RESOLVER_ARG -t "$THREADS" || true) > "$RAW_DIR/subfinder.txt" 2>/dev/null || true; (need_tool assetfinder "${INSTALL[assetfinder]}" && assetfinder --subs-only "$DOMAIN" || true) > "$RAW_DIR/assetfinder.txt" 2>/dev/null || true; if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then (curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' 2>/dev/null | tr '\r' '\n' | tr ' ' '\n' | tr ',' '\n' | sed 's/\\*\\.//g' | sed 's/^\.//' | grep -iE "\\.$DOMAIN$" | sort -u) > "$RAW_DIR/crtsh.txt" || true; fi; if need_tool amass "${INSTALL[amass]}"; then amass enum -passive -d "$DOMAIN" 2>/dev/null | tee "$RAW_DIR/amass.txt" >/dev/null; fi; if need_tool shuffledns "${INSTALL[shuffledns]}" && [ -n "$RESOLVERS" ]; then if [ -n "${WORDLIST:-}" ] && [ -f "$WORDLIST" ]; then shuffledns -d "$DOMAIN" -w "$WORDLIST" -r "$RESOLVERS" -mode bruteforce -t "$THREADS" 2>/dev/null | tee "$RAW_DIR/shuffledns.txt" >/dev/null || true; fi; fi; if [ -n "${CUSTOM_ENUM_CMDS:-}" ]; then IFS=';' read -r -a EXTRA_CMDS <<< "$CUSTOM_ENUM_CMDS"; for cmd in "${EXTRA_CMDS[@]}"; do bash -c "$cmd" 2>/dev/null | tee -a "$RAW_DIR/custom_enum.txt" >/dev/null || true; done; fi; cat "$RAW_DIR"/*.txt 2>/dev/null | grep -iE "\\.$DOMAIN$" | sort -u > "$OUTDIR/enum/all_subdomains.txt"; succ "Collected $(wc -l < "$OUTDIR/enum/all_subdomains.txt" || echo 0) unique subdomains"; }
resolve_subdomains(){ log "[2/6] DNS resolution"; if need_tool dnsx "${INSTALL[dnsx]}"; then DNSX_FLAGS=""; has_flag dnsx -silent && DNSX_FLAGS+=" -silent"; if has_flag dnsx -t; then DNSX_FLAGS+=" -t $THREADS"; elif has_flag dnsx -threads; then DNSX_FLAGS+=" -threads $THREADS"; fi; has_flag dnsx -retries && DNSX_FLAGS+=" -retries 2"; RESOLVER_FLAG=""; if [ -n "$RESOLVER_ARG" ]; then if has_flag dnsx -r; then RESOLVER_FLAG=" -r $RESOLVER_ARG"; elif has_flag dnsx -resolver; then RESOLVER_FLAG=" -resolver $RESOLVER_ARG"; elif has_flag dnsx -resolvers; then RESOLVER_FLAG=" -resolvers $RESOLVER_ARG"; fi; fi; dnsx $DNSX_FLAGS -l "$OUTDIR/enum/all_subdomains.txt" $RESOLVER_FLAG -o "$OUTDIR/enum/resolved.txt" 2>/dev/null || dnsx -l "$OUTDIR/enum/all_subdomains.txt" -o "$OUTDIR/enum/resolved.txt" 2>/dev/null || true; fi; if [ ! -s "$OUTDIR/enum/resolved.txt" ]; then while read -r sub; do if command -v host >/dev/null 2>&1; then host "$sub" >/dev/null 2>&1 && echo "$sub"; elif command -v dig >/dev/null 2>&1; then dig +short "$sub" | grep -qE '^[0-9]' && echo "$sub"; fi; done < "$OUTDIR/enum/all_subdomains.txt" > "$OUTDIR/enum/resolved.txt" 2>/dev/null || true; fi; succ "Resolved $(wc -l < "$OUTDIR/enum/resolved.txt" || echo 0) subdomains"; }
probe_http(){ [ $DO_PROBE -eq 1 ] || return; log "[3/6] HTTP probing"; if need_tool httpx "${INSTALL[httpx]}"; then HTTPX_FLAGS=""; has_flag httpx -silent && HTTPX_FLAGS+=" -silent"; if has_flag httpx -threads; then HTTPX_FLAGS+=" -threads $THREADS"; elif has_flag httpx -t; then HTTPX_FLAGS+=" -t $THREADS"; fi; for f in -follow-redirects -status-code -title -tech-detect -ip -websocket -cdn -content-length; do has_flag httpx "$f" && HTTPX_FLAGS+=" $f"; done; has_flag httpx -rl && HTTPX_FLAGS+=" -rl 100" || (has_flag httpx -rate && HTTPX_FLAGS+=" -rate 100"); httpx -l "$OUTDIR/enum/resolved.txt" $HTTPX_FLAGS -o "$WEB_DIR/httpx_full.txt" 2>/dev/null || httpx -l "$OUTDIR/enum/resolved.txt" -o "$WEB_DIR/httpx_full.txt" 2>/dev/null || true; awk '{print $1}' "$WEB_DIR/httpx_full.txt" | sort -u > "$WEB_DIR/alive_hosts.txt" || true; succ "HTTP alive hosts: $(wc -l < "$WEB_DIR/alive_hosts.txt" 2>/dev/null || echo 0)"; fi; }
collect_urls(){ [ $DO_URLS -eq 1 ] || return; log "[4/6] URL archive collection"; hostlist="$WEB_DIR/alive_hosts.txt"; [ -s "$hostlist" ] || hostlist="$OUTDIR/enum/resolved.txt"; need_tool waybackurls "${INSTALL[waybackurls]}" && cat "$hostlist" | waybackurls | sort -u > "$URL_DIR/waybackurls.txt" 2>/dev/null || true; need_tool gau "${INSTALL[gau]}" && gau --threads "$THREADS" --providers wayback,otx,commoncrawl,github -o "$URL_DIR/gau.txt" "$DOMAIN" 2>/dev/null || true; need_tool waymore "${INSTALL[waymore]}" && waymore -i "$hostlist" -o "$URL_DIR/waymore" -mode U 2>/dev/null || true; need_tool katana "${INSTALL[katana]}" && katana -list "$hostlist" -silent -aff -d 2 -jc -fx -o "$URL_DIR/katana.txt" 2>/dev/null || true; cat "$URL_DIR"/*.txt 2>/dev/null | sort -u > "$URL_DIR/all_urls.txt" || true; succ "Collected $(wc -l < "$URL_DIR/all_urls.txt" 2>/dev/null || echo 0) unique URLs"; }
port_scan(){ [ $DO_PORTS -eq 1 ] || return; log "[5/6] Port scanning"; need_tool naabu "${INSTALL[naabu]}" && naabu -silent -top-ports 1000 -rate 1000 -list "$OUTDIR/enum/resolved.txt" -o "$SCAN_DIR/ports.txt" 2>/dev/null || true; }
nuclei_scan(){ [ $DO_NUCLEI -eq 1 ] || return; log "[6/6] Nuclei scan"; need_tool nuclei "${INSTALL[nuclei]}" && { targets="$WEB_DIR/alive_hosts.txt"; [ -s "$targets" ] || targets="$OUTDIR/enum/resolved.txt"; nuclei -l "$targets" -silent -o "$SCAN_DIR/nuclei.txt" 2>/dev/null || true; }; }
cleanup(){ [ $KEEP_TEMP -eq 1 ] || rm -f "$OUTDIR"/enum/raw/*.tmp 2>/dev/null || true; }
enum_subdomains; resolve_subdomains; probe_http; collect_urls; port_scan; nuclei_scan; cleanup; succ "Done"; exit 0
` +
`# === END ORIGINAL SCRIPT ===
`

func main() {
	args := os.Args[1:]
	if len(args) == 1 && args[0] == "--dump-script" {
		fmt.Print(embeddedScript)
		return
	}
	if len(args) == 2 && args[0] == "--write-script" {
		if err := os.WriteFile(args[1], []byte(embeddedScript), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "spiderco: write error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Embedded script written to", args[1])
		return
	}
	// Prefer local recon.sh if present
	script := "recon.sh"
	if _, err := os.Stat(script); err != nil {
		// materialize embedded
		cacheDir, _ := os.UserCacheDir()
		if cacheDir == "" { cacheDir = os.TempDir() }
		sum := sha256.Sum256([]byte(embeddedScript))
		scriptPath := filepath.Join(cacheDir, "spiderco-"+hex.EncodeToString(sum[:8])+".sh")
		if _, err2 := os.Stat(scriptPath); err2 != nil {
			_ = os.WriteFile(scriptPath, []byte(embeddedScript), 0o755)
		}
		script = scriptPath
	}
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "spiderco: %v\n", err)
		os.Exit(1)
	}
}
