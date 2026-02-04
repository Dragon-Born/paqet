//go:build !nopcap

package main

import (
	"paqet/cmd/dump"

	"github.com/spf13/cobra"
)

func registerPlatformCommands(rootCmd *cobra.Command) {
	rootCmd.AddCommand(dump.Cmd)
}
