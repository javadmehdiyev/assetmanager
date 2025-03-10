package main

import (
	"fmt"
	"os"

	"network-asset-manager/internal/ui"
)

func main() {
	if err := ui.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
