// Smuggled — HTTP Request Smuggling detection CLI
// Usage: smuggled scan [flags] [url...]
package main

import (
	"os"

	"github.com/smuggled/smuggled/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
