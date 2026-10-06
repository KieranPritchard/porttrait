package cmd

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	bannergrabbing "kpritchard.co.uk/porttrait/internal/banner-grabbing"
	"kpritchard.co.uk/porttrait/internal/fingerprinting"
	"kpritchard.co.uk/porttrait/internal/input"
)

// Stores the struct for the scan command
type ScanResult struct {
	Banner string
	Port string
	Matches []fingerprinting.MatchResult
}

// Stores the channel for the scan workers
var scanWorkerChannel = make(chan []ScanResult, 100)

// Defines the worker function for the scan command
func scanWorker(target string, port string, timeout int) {
	// Stores the result of the scan
	var result ScanResult

	// Runs the tcp scanner
	banner, err := bannergrabbing.GrabTCPBanners(target + ":" + port, time.Duration(timeout)*time.Second)
	if err != nil {
		fmt.Println("Error occured: ", err)
	}

	// Adds the banner and port to the result struct
	result.Banner = banner
	result.Port = port

	// Attempts to match the banner
	matches, err := fingerprinting.MatchBanners(banner)
	if err != nil {
		fmt.Println("Error occured: ", err)
	}

	// Outputs each of the matches
	for _, match := range matches {
		// Adds the match to the result struct
		result.Matches = append(result.Matches, match)
	}

	// Sends the result to the channel
	scanWorkerChannel <- []ScanResult{result}
}

// Defines the scan command
var scanCmd = &cobra.Command{
	Use: "scan",
	Short: "Scans either the specified port(s) or all the ports for open services",

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

		// Checks if the ports are empty
		if ports == "" {
			// Loops over all the ports
			for port := 1; port <= 65535; port++ {
				// Converts the port to a string
				portStr := strconv.Itoa(port)

				// Runs the scan worker in a goroutine
				go scanWorker(target, portStr, timeout)
			}
			
			// Loops over all the ports
			for port := 1; port <= 65535; port++ {
				// Receives the result from the channel
				result := <-scanWorkerChannel

				// Outputs the result
				fmt.Println("Port: ", result[0].Port)
				fmt.Println("Banner: ", result[0].Banner)
				fmt.Println("Matches: ", result[0].Matches)
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
				for _, match := range matches {
					fmt.Println(match)
				}
			}
		}
	},
}

func init() {
	// Adds the command to the root command
	rootCmd.AddCommand(scanCmd)
}