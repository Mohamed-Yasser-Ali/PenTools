# PenTools - SpiderCo Recon Toolkit

Single-script (bash) reconnaissance workflow, installable wrapper via `spiderco` Go binary.

## Features
- Passive + optional brute-force subdomain enumeration (subfinder, assetfinder, amass, shuffledns, **crt.sh**)
- DNS resolution (dnsx with graceful fallback)
- HTTP probing (httpx) with tech + title + status + IP + CDN detection
- URL collection (waybackurls, gau, waymore, katana) and consolidation
- Optional port scan (naabu)
- Optional nuclei scanning
- Custom enumeration command hook (`CUSTOM_ENUM_CMDS`)
- Dynamic flag detection for mixed tool versions
- Colored logging & modular steps

## Install (Go users)
```bash
go install github.com/Mohamed-Yasser-Ali/PenTools/cmd/spiderco@latest
```
Ensure `$GOPATH/bin` (or `$HOME/go/bin`) is in PATH, then:
```bash
spiderco -d target.com --full
```

## SpiderCo Wrapper Options
```bash
# Dump embedded script to see full source
spiderco --dump-script

# Write embedded script to file (useful for customization)
spiderco --write-script recon.sh
```

Or clone and run script directly:
```bash
git clone https://github.com/Mohamed-Yasser-Ali/PenTools.git
cd PenTools
./recon.sh -d target.com --full
```

## Quick Start
```bash
# Full recon (enum + resolve + probe + urls + ports + nuclei)
spiderco -d target.com --full

# Faster (no ports / nuclei, still enum + probe + urls)
spiderco -d target.com

# Full with more threads + keep temp files
spiderco -d target.com --full -t 100 --keep-temp

# Use curated resolvers list
spiderco -d target.com --full --resolvers resolvers.txt

# Custom output directory
spiderco -d target.com --full -o recon-target

# Supply brute-force wordlist (used by shuffledns if available)
WORDLIST=wordlist.txt spiderco -d target.com --full --resolvers resolvers.txt

# Add extra enumeration commands (semicolon separated)
CUSTOM_ENUM_CMDS="crtsh.py -d target.com;another_enum_tool target.com" \
  spiderco -d target.com --full

# Skip URL collection and probing (just enumerate + resolve)
spiderco -d target.com --no-urls --no-probe

# Only add ports + nuclei later (if you already enumerated)
spiderco -d target.com --ports --nuclei
```

## Enumeration Sources
The script automatically queries multiple subdomain sources:
- **subfinder**: Passive DNS aggregation
- **assetfinder**: Passive subdomain discovery 
- **amass**: OSINT-based enumeration (if installed)
- **crt.sh**: Certificate transparency logs (requires curl + jq)
- **shuffledns**: DNS bruteforce (requires custom wordlist via `WORDLIST` env var)
- **Custom commands**: Via `CUSTOM_ENUM_CMDS` environment variable

## Flags Summary
| Flag | Description |
|------|-------------|
| -d / --domain | Apex domain (required) |
| -o / --outdir | Output directory (default: recon-<domain>) |
| -t / --threads | Concurrency (default: 50) |
| --resolvers FILE | Custom resolvers list |
| --no-urls | Skip URL archival/crawling stage |
| --no-probe | Skip HTTP probing stage |
| --ports | Run naabu port scan |
| --nuclei | Run nuclei scan |
| --full | Enable URLs + ports + nuclei |
| --keep-temp | Retain temp/intermediate files |
| --help / -h | Show help header |
| --version | Print version |

## Environment Variables
| Variable | Purpose |
|----------|---------|
| WORDLIST | Path to wordlist for shuffledns brute-force |
| CUSTOM_ENUM_CMDS | Extra enum commands separated by `;` (each should output subdomains) |

## Output Structure

```
<outdir>/
  enum/
    raw/              # Raw tool outputs
    all_subdomains.txt  # Only valid subdomains (no notes, IPs, or records)
    resolved.txt
  web/
    httpx_full.txt
    alive_hosts.txt
  urls/
    waybackurls.txt
    gau.txt
    katana.txt
    waymore/ (folder produced by waymore)
    all_urls.txt
  scans/
    ports.txt
    nuclei.txt
```

**Note:** `all_subdomains.txt` is now strictly filtered to include only valid subdomain names, excluding tool notes, IPs, and other records.

## Tool Installation Cheat Sheet
(Install only what you need; Go bin path must be in $PATH.)
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/owasp-amass/amass/v4/...@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
pip install waymore
```

## Recommended Workflow
1. Initial wide passive recon: `./recon.sh -d target.com`  
2. Deep dive (ports + nuclei): `./recon.sh -d target.com --full -t 100`  
3. Focused brute (with wordlist + resolvers): `WORDLIST=wordlist.txt ./recon.sh -d target.com --full --resolvers resolvers.txt`  
4. Feed `urls/all_urls.txt` into specialized fuzzers or parameter analyzers.

## Notes
- Script auto-detects supported flags for dnsx/httpx; mixed tool versions are handled.
- If `dnsx` fails, it falls back to simple resolution (slower).
- Add / prune resolvers in `resolvers.txt` for stability vs. diversity.

## Disclaimer
Use only against assets you have permission to test.

## License
Add a license of your choice (e.g., MIT) if you plan to share publicly.

---
Feel free to open issues / extend the script. Happy hunting!
