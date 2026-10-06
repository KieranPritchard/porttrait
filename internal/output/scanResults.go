package output

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"kpritchard.co.uk/porttrait/internal/fingerprinting"
)

// Stores the struct for the scan command
type ScanResult struct {
	Banner   string
	Port     string
	Protocol string
	State    string
	Matches  []fingerprinting.MatchResult
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
func PrintResults(results []ScanResult) {
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
func PrintVerbose(results []ScanResult) {
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