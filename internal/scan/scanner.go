package scan

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"kpritchard.co.uk/porttrait/internal/output"
)

// Runs the worker pool over the given ports and protocols and outputs the results
func RunScan(target string, portList []string, protocols []string, timeout int, showUnresponsive bool, scanVerbose bool) {
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

	// Sets up a context that cancels on SIGINT/SIGTERM for graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Keep this below `ulimit -n`
	numWorkers := 5000
	if len(jobList) < numWorkers {
		numWorkers = len(jobList)
	}

	// Stores the channels for the jobs and the results
	jobs := make(chan scanJob, numWorkers)
	results := make(chan output.ScanResult, numWorkers)
	var wg sync.WaitGroup

	// Starts the workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go ScanWorker(ctx, target, timeout, showUnresponsive, jobs, results, &wg)
	}

	// Feeds the jobs in from a separate goroutine
	go func() {
		for _, job := range jobList {
			select {
			case jobs <- job:
			case <-ctx.Done():
				// Context cancelled, stop sending jobs
				break
			}
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
	var found []output.ScanResult
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
		output.PrintResults(found)
		if scanVerbose {
			output.PrintVerbose(found)
		}
	}

	// Shows whether the scan was interrupted or completed fully
	elapsed := time.Since(start).Round(time.Millisecond)
	if ctx.Err() != nil {
		fmt.Printf("\nScan interrupted — %d open port(s) found in %s\n", len(found), elapsed)
	} else {
		fmt.Printf("\n%d open port(s) found in %s\n", len(found), elapsed)
	}
}