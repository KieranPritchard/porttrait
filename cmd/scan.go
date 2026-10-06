package cmd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	bannergrabbing "kpritchard.co.uk/porttrait/internal/banner-grabbing"
	"kpritchard.co.uk/porttrait/internal/fingerprinting"
	"kpritchard.co.uk/porttrait/internal/input"
)

// Stores the protocol flag for the scan command (tcp, udp or both)
var scanProtocol string

// Stores the verbose flag for the scan command
var scanVerbose bool

// Stores the struct for the scan command
type ScanResult struct {
	Banner   string
	Port     string
	Protocol string
	State    string
	Matches  []fingerprinting.MatchResult
}

// Stores a single unit of work for the workers
type scanJob struct {
	Port     string
	Protocol string
}

// Defines the worker function for the scan command
func scanWorker(target string, timeout int, showUnresponsive bool, jobs <-chan scanJob, results chan<- ScanResult, wg *sync.WaitGroup) {
	// Marks the worker as done when the jobs channel is closed
	defer wg.Done()

	// Stores the timeout as a duration
	duration := time.Duration(timeout) * time.Second

	// Each worker pulls jobs until the jobs channel is closed
	for job := range jobs {
		// Builds the address (also works for IPv6)
		address := net.JoinHostPort(target, job.Port)

		// Stores the banner and the state of the port
		var banner string
		var err error
		state := "open"

		// Runs the scanner for the protocol
		if job.Protocol == "udp" {
			banner, err = bannergrabbing.GrabUDPBanners(address, duration)

			// No reply to the probe means the port is open or filtered
			if errors.Is(err, bannergrabbing.ErrNoResponse) {
				// Skips these on full scans, since every filtered port would show up
				if !showUnresponsive {
					continue
				}
				state = "open|filtered"
				err = nil
			}
		} else {
			banner, err = bannergrabbing.GrabTCPBanners(address, duration)
		}

		if err != nil {
			// Closed port, so skip it instead of printing an error for every port
			continue
		}

		// Stores the result of the scan
		var result ScanResult

		// Adds the banner, port, protocol and state to the result struct
		result.Banner = banner
		result.Port = job.Port
		result.Protocol = job.Protocol
		result.State = state

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

// Returns the first line of the banner, shortened to fit the table
func shortBanner(banner string, max int) string {
	// Takes the first line only
	line := strings.TrimSpace(strings.SplitN(strings.TrimSpace(banner), "\n", 2)[0])
	if line == "" {
		return "-"
	}

	// Shortens long lines
	runes := []rune(line)
	if len(runes) > max {
		return string(runes[:max-3]) + "..."
	}
	return line
}

// Returns the service and version columns for a result
func describeMatches(matches []fingerprinting.MatchResult) (string, string) {
	if len(matches) == 0 {
		return "-", "-"
	}

	// Uses the first match for the table
	first := matches[0]
	service := strings.TrimSpace(first.Vendor + " " + first.Product)
	if service == "" {
		service = "-"
	}
	if len(matches) > 1 {
		service += fmt.Sprintf(" (+%d)", len(matches)-1)
	}

	version := first.Version
	if version == "" {
		version = "-"
	}

	return service, version
}

// Outputs the results as a table
func printResults(results []ScanResult) {
	// Creates the table writer
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

	// Outputs the header
	fmt.Fprintln(w, "PORT\tSTATE\tSERVICE\tVERSION\tBANNER")

	// Outputs each of the rows
	for _, r := range results {
		service, version := describeMatches(r.Matches)
		fmt.Fprintf(w, "%s/%s\t%s\t%s\t%s\t%s\n", r.Port, r.Protocol, r.State, service, version, shortBanner(r.Banner, 50))
	}

	w.Flush()
}

// Outputs the full banner and every match for each result
func printVerbose(results []ScanResult) {
	for _, r := range results {
		fmt.Printf("\n--- %s/%s ---\n", r.Port, r.Protocol)

		// Outputs the full banner, indented
		if strings.TrimSpace(r.Banner) == "" {
			fmt.Println("  (no banner)")
		} else {
			for _, line := range strings.Split(strings.TrimSpace(r.Banner), "\n") {
				fmt.Println("  " + strings.TrimSpace(line))
			}
		}

		// Outputs every match
		for _, m := range r.Matches {
			fmt.Printf("  match: %s %s %s\n", m.Vendor, m.Product, m.Version)
		}
	}
}

// Runs the worker pool over the given ports and protocols and outputs the results
func runScan(target string, portList []string, protocols []string, timeout int, showUnresponsive bool) {
	// Builds a job for each port and protocol
	jobList := make([]scanJob, 0, len(portList)*len(protocols))
	for _, port := range portList {
		for _, protocol := range protocols {
			jobList = append(jobList, scanJob{Port: port, Protocol: protocol})
		}
	}

	// Outputs the scan header
	fmt.Printf("Scanning %s (%s) - %d ports\n\n", target, strings.Join(protocols, ", "), len(portList))
	start := time.Now()

	// Keep this below `ulimit -n`
	numWorkers := 500
	if len(jobList) < numWorkers {
		numWorkers = len(jobList)
	}

	// Stores the channels for the jobs and the results
	jobs := make(chan scanJob, numWorkers)
	results := make(chan ScanResult, numWorkers)
	var wg sync.WaitGroup

	// Starts the workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go scanWorker(target, timeout, showUnresponsive, jobs, results, &wg)
	}

	// Feeds the jobs in from a separate goroutine
	go func() {
		for _, job := range jobList {
			jobs <- job
		}
		// Tells the workers there is no more work
		close(jobs)
	}()

	// Closes results once all the workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collects every result so they can be sorted before output
	var found []ScanResult
	for result := range results {
		found = append(found, result)
	}

	// Sorts by port number, then protocol
	sort.Slice(found, func(i, j int) bool {
		a, _ := strconv.Atoi(found[i].Port)
		b, _ := strconv.Atoi(found[j].Port)
		if a != b {
			return a < b
		}
		return found[i].Protocol < found[j].Protocol
	})

	// Outputs the results
	if len(found) == 0 {
		fmt.Println("No open ports found")
	} else {
		printResults(found)
		if scanVerbose {
			printVerbose(found)
		}
	}

	// Outputs the summary
	fmt.Printf("\n%d open port(s) found in %s\n", len(found), time.Since(start).Round(time.Millisecond))
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
		runScan(target, portList, protocols, timeout, showUnresponsive)
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