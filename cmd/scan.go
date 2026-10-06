package cmd

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	bannergrabbing "kpritchard.co.uk/porttrait/internal/banner-grabbing"
	"kpritchard.co.uk/porttrait/internal/fingerprinting"
	"kpritchard.co.uk/porttrait/internal/input"
)

// Stores the struct for the scan command
type ScanResult struct {
	Banner  string
	Port    string
	Matches []fingerprinting.MatchResult
}

// Defines the worker function for the scan command
func scanWorker(target string, timeout int, jobs <-chan string, results chan<- ScanResult, wg *sync.WaitGroup) {
	// Marks the worker as done when the jobs channel is closed
	defer wg.Done()

	// Each worker pulls ports until the jobs channel is closed
	for port := range jobs {
		// Runs the tcp scanner
		banner, err := bannergrabbing.GrabTCPBanners(target+":"+port, time.Duration(timeout)*time.Second)
		if err != nil {
			// Closed/filtered port, so skip it instead of printing an error for every port
			continue
		}

		// Stores the result of the scan
		var result ScanResult

		// Adds the banner and port to the result struct
		result.Banner = banner
		result.Port = port

		// Attempts to match the banner
		matches, err := fingerprinting.MatchBanners(banner)
		if err != nil {
			fmt.Println("Error occured: ", err)
		}

		// Adds the matches to the result struct
		result.Matches = append(result.Matches, matches...)

		// Sends the result to the channel
		results <- result
	}
}

// Runs the worker pool over the given ports and outputs the results
func runScan(target string, portList []string, timeout int) {
	// Keep this below `ulimit -n`
	numWorkers := 500
	if len(portList) < numWorkers {
		numWorkers = len(portList)
	}

	// Stores the channels for the jobs and the results
	jobs := make(chan string, numWorkers)
	results := make(chan ScanResult, numWorkers)
	var wg sync.WaitGroup

	// Starts the workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go scanWorker(target, timeout, jobs, results, &wg)
	}

	// Feeds the ports in from a separate goroutine
	go func() {
		for _, port := range portList {
			jobs <- port
		}
		// Tells the workers there is no more work
		close(jobs)
	}()

	// Closes results once all the workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Only open ports arrive here
	for result := range results {
		fmt.Println("Port: ", result.Port)
		fmt.Println("Banner: ", result.Banner)
		fmt.Println("Matches: ", result.Matches)
	}
}

// Defines the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
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
				return
			}
		} else {
			_, err := input.PrepareIP(target)
			if err != nil {
				fmt.Println("Error occured: ", err)
				return
			}
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

		// Runs the scan over the ports
		runScan(target, portList, timeout)
	},
}

func init() {
	// Adds the command to the root command
	rootCmd.AddCommand(scanCmd)
}