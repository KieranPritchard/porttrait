package scan

import (
	"fmt"
	"net"
	"sync"
	"time"

	"kpritchard.co.uk/porttrait/internal/banners"
	"kpritchard.co.uk/porttrait/internal/fingerprinting"
	"kpritchard.co.uk/porttrait/internal/output"
)

// Stores a single unit of work for the workers
type scanJob struct {
	Port     string
	Protocol string
}

// Defines the worker function for the scan command
func ScanWorker(target string, timeout int, showUnresponsive bool, jobs <-chan scanJob, results chan<- output.ScanResult, wg *sync.WaitGroup) {
	// Marks the worker as done when the jobs channel is closed
	defer wg.Done()

	// Stores the timeout as a duration
	duration := time.Duration(timeout) * time.Second

	// Each worker pulls jobs until the jobs channel is closed
	for job := range jobs {
		// Stores the banner, matches and the state of the port
		var banner string
		var matches []fingerprinting.MatchResult
		var err error
		state := "open"

		// Runs the scanner for the protocol
		if job.Protocol == "udp" {
			// Sends the probes for the port and matches the raw reply
			banner, matches, state, err = ScanUDP(target, job.Port, duration)

			// Skips silent UDP ports on full scans, since every filtered port would show up
			if err == nil && state == "open|filtered" && !showUnresponsive {
				continue
			}
		} else {
			// Builds the address (also works for IPv6)
			address := net.JoinHostPort(target, job.Port)

			// Runs the tcp scanner
			banner, err = banners.GrabTCPBanners(address, duration)
			if err == nil {
				// Attempts to match the banner
				matches, err = fingerprinting.MatchBanners(banner)
				if err != nil {
					fmt.Println("Error occured: ", err)
					err = nil
				}
			}
		}

		if err != nil {
			// Closed port, so skip it instead of printing an error for every port
			continue
		}

		// Stores the result of the scan
		var result output.ScanResult

		// Adds the banner, port, protocol, state and matches to the result struct
		result.Banner = banner
		result.Port = job.Port
		result.Protocol = job.Protocol
		result.State = state
		result.Matches = matches

		// Sends the result to the channel
		results <- result
	}
}