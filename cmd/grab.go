package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	bannergrabbing "kpritchard.co.uk/service-fingerprinter/internal/banner-grabbing"
	"kpritchard.co.uk/service-fingerprinter/internal/fingerprinting"
)

// Stores the variables that are needed by the command
var domain string
var ports string

// Defines the grab command
var grabCmd = &cobra.Command{
	Use: "grab",
	Short: "Grabs the banner of the specified port(s)",

	// Handles the logic of the command when called
	Run: func(cmd *cobra.Command, args []string) {
		// runs the tcp scanner
		banner, err := bannergrabbing.GrabTCPBanners(domain + ":" + ports, 10*time.Second)
		if err != nil {
			fmt.Println(err)
		}

		fmt.Println(banner)

		// Attempts to match the banner
		matches, err := fingerprinting.MatchBanners(banner)
		if err != nil {
			fmt.Println(err)
		}

		// Ouputs each of the matches
		for match := range matches {
			fmt.Println(match)
		}
	},
}

func init() {
	grabCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain to be targeted")
	grabCmd.Flags().StringVarP(&ports, "ports", "p", "", "Ports to be targeted")

	// Adds the command to the root command
	rootCmd.AddCommand(grabCmd)
}