package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	bannergrabbing "kpritchard.co.uk/service-fingerprinter/internal/banner-grabbing"
)

// Defines the grab command
var grabCmd = &cobra.Command{
	Use: "grab",
	Short: "Grabs the banner of the specified port(s)",

	// Handles the logic of the command when called
	Run: func(cmd *cobra.Command, args []string) {
		// runs the tcp scanner
		banner, err := bannergrabbing.GrabTCPBanners("scanme.nmap.org:22", 10*time.Second)
		if err != nil {
			fmt.Println(err)
		}

		// Outputs the banner
		fmt.Println(banner)
	},
}

func init() {
	rootCmd.AddCommand(grabCmd)
}