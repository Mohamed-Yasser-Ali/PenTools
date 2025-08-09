package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// NOTE: Embedded script snapshot (recon.sh v1.3.1). Keep in sync when updating the bash script.
// For full fidelity, users can still place an updated recon.sh alongside the binary; that file takes precedence.
const embeddedScript = `#!/bin/bash
` +
`# Embedded recon.sh (spiderco) - if you modify this, recompile spiderco.
` +
`set -Eeuo pipefail
IFS=$'\n\t'
` +
`# (Truncated for embedded runtime) Encourage cloning repo for latest features.
` +
`if [[ "$1" == "--embedded-note" ]]; then echo "This is the embedded minimal launcher. Clone repo for full script."; exit 0; fi
` +
`# Delegate to full recon.sh if present in same directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/recon.sh" ]]; then exec bash "$SCRIPT_DIR/recon.sh" "$@"; fi
echo "[WARN] Full recon.sh not found; running embedded stub." >&2
echo "[ERR] Embedded stub does not contain full functionality. Clone https://github.com/Mohamed-Yasser-Ali/PenTools for latest." >&2
exit 1
`

func main() {
	// Flags for wrapper itself (must be parsed separately if we want wrapper-only flags)
	dump := flag.Bool("dump-script", false, "Print embedded recon.sh to stdout and exit")
	out := flag.String("write-script", "", "Write embedded recon.sh to specified path and exit")
	flag.CommandLine.Init("spiderco", flag.ContinueOnError)
	flag.CommandLine.Usage = func() {
		fmt.Fprintf(os.Stderr, "spiderco wrapper\nUsage: spiderco [wrapper flags] -- [recon args]\nWrapper flags:\n  -dump-script        Print embedded script\n  -write-script PATH  Write embedded script to PATH\n")
	}
	// Parse only wrapper flags appearing before a standalone -- or before first recon flag starting with -d/-o/etc.
	// Simplicity: parse all; if unknown flags (belonging to recon.sh) cause failure, ignore by re-running via script.
	_ = flag.CommandLine.Parse(os.Args[1:])

	if *dump {
		fmt.Print(embeddedScript)
		return
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(embeddedScript), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "spiderco: write error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Embedded script written to", *out)
		return
	}

	// Prefer local recon.sh if present (user may have newer version)
	script := "recon.sh"
	if _, err := os.Stat(script); err != nil {
		// Materialize embedded copy into a cache path under user's cache dir for reuse
		cacheDir, _ := os.UserCacheDir()
		if cacheDir == "" { cacheDir = os.TempDir() }
		hash := sha256.Sum256([]byte(embeddedScript))
		scriptPath := filepath.Join(cacheDir, "spiderco-"+hex.EncodeToString(hash[:8]) + ".sh")
		if _, err2 := os.Stat(scriptPath); err2 != nil {
			_ = os.WriteFile(scriptPath, []byte(embeddedScript), 0o755)
		}
		script = scriptPath
	}

	// Pass through all original args (excluding wrapper-only flags that were consumed)
	// Simplicity: re-build args from leftover (flag.Args())
	passArgs := flag.Args()
	cmd := exec.Command("bash", append([]string{script}, passArgs...)...)
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
