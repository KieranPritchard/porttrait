package cmd

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
	bannergrabbing "kpritchard.co.uk/porttrait/internal/banner-grabbing"
	"kpritchard.co.uk/porttrait/internal/fingerprinting"
	"kpritchard.co.uk/porttrait/internal/input"
)

// Defines the grab command
var grabCmd = &cobra.Command{
	Use: "grab",
	Short: "Grabs the banner of the specified port(s)",

	// Handles the logic of the command when called
	Run: func(cmd *cobra.Command, args []string) {
		// Domain regex: RFC 1035 / RFC 1123 compliant label rules
		var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

		// Checks if there is a domain
		if domainRegex.MatchString(target) {
			_, err := input.PrepareDomain(target)
			if err != nil {
				fmt.Println("Error occured: ", err)
			}
		} else {
			_, err := input.PrepareIP(target)
			if err != nil {
				fmt.Println("Error occured: ", err)
			}
		}

		// Checks if there are commas in the ports
		if strings.Contains(ports, ",") {
			// Stores the split ports in a variable
			separatedPorts := strings.Split(ports, ",")

			// Loops over each of the ports
			for _, port := range separatedPorts{
				// Removes the white space from the port
				port, err := input.PreparePort(port)
				if err != nil {
					fmt.Println("Error occured: ", err)
				}
				
				// runs the tcp scanner
				banner, err := bannergrabbing.GrabTCPBanners(target + ":" + port, time.Duration(timeout)*time.Second)
				if err != nil {
					fmt.Println("Error occured: ", err)
				}

				fmt.Println(banner)

				// Attempts to match the banner
				matches, err := fingerprinting.MatchBanners(banner)
				if err != nil {
					fmt.Println("Error occured: ", err)
				}

				// Ouputs each of the matches
				for match := range matches {
					fmt.Println(match)
				}
			}
		}
	},
}

func init() {
	grabCmd.Flags().StringVarP(&target, "target", "t", "", "Domain to be targeted")
	grabCmd.Flags().StringVarP(&ports, "ports", "p", "", "Port to be targeted")

	// Adds the command to the root command
	rootCmd.AddCommand(grabCmd)
}