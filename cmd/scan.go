package cmd

import (
	"github.com/spf13/cobra"
)

// Defines the scan command
var scanCmd = &cobra.Command{
	Use: "scan",
	Short: "Scans either the specified port(s) or all the ports for open services",

	// Handles the logic of the command when called
	Run: func(cmd *cobra.Command, args []string) {
		
	}
}