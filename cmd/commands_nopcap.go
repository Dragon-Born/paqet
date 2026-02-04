//go:build nopcap

package main

import "github.com/spf13/cobra"

func registerPlatformCommands(rootCmd *cobra.Command) {
	// dump command requires libpcap, not available in nopcap builds
}
