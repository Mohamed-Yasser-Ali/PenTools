#!/bin/bash

# Recon script for bug bounty hunting
# Usage: ./recon.sh target.com

set -e

REQUIRED_TOOLS=(subfinder sublist3r assetfinder httpx waymore waybackurls)
INSTALL_COMMANDS=(
	"go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
	"pip install sublist3r"
	"go install github.com/tomnomnom/assetfinder@latest"
	"go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
	"pip install waymore"
	"go install github.com/tomnomnom/waybackurls@latest"
)

for i in "${!REQUIRED_TOOLS[@]}"; do
	if ! command -v "${REQUIRED_TOOLS[$i]}" &> /dev/null; then
		echo "[!] ${REQUIRED_TOOLS[$i]} is not installed."
		echo "    To install: ${INSTALL_COMMANDS[$i]}"
	fi
done

if [ $# -ne 1 ]; then
	echo "Usage: $0 <domain>"
	exit 1
fi

DOMAIN=$1
OUTDIR="recon-$DOMAIN"
mkdir -p "$OUTDIR"

echo "[+] Finding subdomains for $DOMAIN..."
subfinder -d "$DOMAIN" -silent > "$OUTDIR/subfinder.txt" 2>/dev/null || true
sublist3r -d "$DOMAIN" -o "$OUTDIR/sublist3r.txt" 2>/dev/null || true
assetfinder --subs-only "$DOMAIN" > "$OUTDIR/assetfinder.txt" 2>/dev/null || true

cat "$OUTDIR/subfinder.txt" "$OUTDIR/sublist3r.txt" "$OUTDIR/assetfinder.txt" | sort -u > "$OUTDIR/all_subs.txt"

echo "[+] Probing for alive subdomains with httpx..."
httpx -l "$OUTDIR/all_subs.txt" -status-code -title -silent > "$OUTDIR/httpx_full.txt" 2>/dev/null || true
cat "$OUTDIR/httpx_full.txt" | awk '{print $1}' > "$OUTDIR/alive.txt"

echo "[+] Running waymore and waybackurls on alive subdomains..."
waymore -i "$OUTDIR/alive.txt" -o "$OUTDIR/waymore.txt" 2>/dev/null || true
cat "$OUTDIR/alive.txt" | waybackurls > "$OUTDIR/waybackurls.txt" 2>/dev/null || true

echo "[+] Recon complete. Results saved in $OUTDIR/"
