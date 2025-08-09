package main

import (
	"fmt"
	"os"
	"os/exec"
)

// spiderco is a thin Go wrapper that embeds the bash script recon.sh so users can `go install`.
// It forwards arguments to the local script after ensuring it's present.
func main() {
	script := "recon.sh"
	if _, err := os.Stat(script); err != nil {
		fmt.Fprintf(os.Stderr, "spiderco: cannot find %s in current directory. Clone the repo containing recon.sh.\n", script)
		os.Exit(1)
	}
	cmd := exec.Command("bash", append([]string{script}, os.Args[1:]...)...)
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
