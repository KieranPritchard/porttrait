package cmd

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"kpritchard.co.uk/porttrait/internal/input"
	"kpritchard.co.uk/porttrait/internal/scan"
)

// Stores the protocol flag for the scan command (tcp, udp or both)
var scanProtocol string

// Stores the verbose flag for the scan command
var scanVerbose bool

// Defines the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scans either the specified port(s) or all the ports for open services",

	// Handles the logic of the command when called
	Run: func(cmd *cobra.Command, args []string) {
		// Domain regex: RFC 1035 / RFC 1123 compliant label rules
		var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

		// Checks if there is a domain
		if domainRegex.MatchString(target) || target == "localhost" {
			_, err := input.PrepareDomain(target)
			if err != nil {
				fmt.Println("Error occured: ", err)
				return
			}
		} else {
			_, err := input.PrepareIP(target)
			if err != nil {
				fmt.Println("Error occured: ", err)
				return
			}
		}

		// Stores the protocols to scan
		var protocols []string

		// Works out which protocols to use
		switch strings.ToLower(scanProtocol) {
		case "tcp":
			protocols = []string{"tcp"}
		case "udp":
			protocols = []string{"udp"}
		case "both":
			protocols = []string{"tcp", "udp"}
		default:
			fmt.Println("Error occured: protocol must be tcp, udp or both")
			return
		}

		// Stores the ports to scan
		var portList []string

		// Checks if the ports are empty
		if ports == "" {
			// Loops over all the ports
			for port := 1; port <= 65535; port++ {
				// Converts the port to a string
				portList = append(portList, strconv.Itoa(port))
			}
		} else {
			// Loops over each of the comma separated ports (also handles a single port)
			for _, port := range strings.Split(ports, ",") {
				// Removes the white space from the port
				preparedPort, err := input.PreparePort(port)
				if err != nil {
					fmt.Println("Error occured: ", err)
					continue
				}

				portList = append(portList, preparedPort)
			}
		}

		// Only shows silent UDP ports when specific ports were requested
		showUnresponsive := ports != ""

		// Runs the scan over the ports
		scan.RunScan(target, portList, protocols, timeout, showUnresponsive, scanVerbose)
	},
}

func init() {
	// Adds the protocol flag to the scan command
	scanCmd.Flags().StringVar(&scanProtocol, "protocol", "both", "Protocol to scan: tcp, udp or both")

	// Adds the verbose flag to the scan command
	scanCmd.Flags().BoolVarP(&scanVerbose, "verbose", "v", false, "Show the full banner and every match for each port")

	// Adds the command to the root command
	rootCmd.AddCommand(scanCmd)
}