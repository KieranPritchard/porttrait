package cmd

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"kpritchard.co.uk/porttrait/internal/banners"
	"kpritchard.co.uk/porttrait/internal/fingerprinting"
	"kpritchard.co.uk/porttrait/internal/input"
)

// Stores the protocol flag for the grab command (tcp, udp or both)
var grabProtocol string

// Stores the result of grabbing a single port
type grabResult struct {
	Port     string
	Protocol string
	State    string
	Banner   string
	Err      error
	Matches  []fingerprinting.MatchResult
}

// Works out which protocols to use from the flag
func parseProtocols(value string) ([]string, error) {
	switch strings.ToLower(value) {
	case "tcp":
		return []string{"tcp"}, nil
	case "udp":
		return []string{"udp"}, nil
	case "both":
		return []string{"tcp", "udp"}, nil
	}
	return nil, errors.New("protocol must be tcp, udp or both")
}

// Grabs the banner for a single port and protocol
func grabOne(target string, port string, protocol string, timeout time.Duration) grabResult {
	// Stores the result of the grab
	result := grabResult{Port: port, Protocol: protocol, State: "open"}

	// Builds the address (also works for IPv6)
	address := net.JoinHostPort(target, port)

	// Stores the banner and the error
	var banner string
	var err error

	// Runs the scanner for the protocol
	if protocol == "udp" {
		banner, err = banners.GrabUDPBanners(address, timeout)

		// No reply to the probe means the port is open or filtered
		if errors.Is(err, banners.ErrNoResponse) {
			result.State = "open|filtered"
			err = nil
		}
	} else {
		banner, err = banners.GrabTCPBanners(address, timeout)
	}

	// The port was specifically requested, so the failure is kept and shown
	if err != nil {
		result.State = "closed"
		result.Err = err
		return result
	}

	// Adds the banner to the result struct
	result.Banner = banner

	// Attempts to match the banner
	matches, err := fingerprinting.MatchBanners(banner)
	if err != nil {
		fmt.Println("Error occured: ", err)
	}

	// Adds the matches to the result struct
	result.Matches = matches

	return result
}

// Outputs a single result as a block
func printGrabResult(r grabResult) {
	// Outputs the port and state
	fmt.Printf("%s/%s  %s\n", r.Port, r.Protocol, r.State)

	// Closed ports only show the reason
	if r.State == "closed" {
		fmt.Printf("  Reason:  %v\n\n", r.Err)
		return
	}

	// Outputs the matches
	if len(r.Matches) == 0 {
		fmt.Println("  Service: -")
	}
	for i, m := range r.Matches {
		label := "Service:"
		if i > 0 {
			label = "        "
		}
		name := strings.TrimSpace(m.Vendor + " " + m.Product)
		if name == "" {
			name = "-"
		}
		version := ""
		if m.Version != "" {
			version = " (v" + m.Version + ")"
		}
		fmt.Printf("  %s %s%s\n", label, name, version)
	}

	// Outputs the full banner, indented
	if strings.TrimSpace(r.Banner) == "" {
		fmt.Println("  Banner:  (none)")
	} else {
		fmt.Println("  Banner:")
		for _, line := range strings.Split(strings.TrimSpace(r.Banner), "\n") {
			fmt.Println("    " + strings.TrimSpace(line))
		}
	}

	fmt.Println()
}

// Defines the grab command
var grabCmd = &cobra.Command{
	Use:   "grab",
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
				return
			}
		} else {
			_, err := input.PrepareIP(target)
			if err != nil {
				fmt.Println("Error occured: ", err)
				return
			}
		}

		// Works out which protocols to use
		protocols, err := parseProtocols(grabProtocol)
		if err != nil {
			fmt.Println("Error occured: ", err)
			return
		}

		// Checks that at least one port was given
		if strings.TrimSpace(ports) == "" {
			fmt.Println("Error occured: no ports specified, use -p")
			return
		}

		// Stores the ports to grab
		var portList []string

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

		// Stops if none of the ports were valid
		if len(portList) == 0 {
			return
		}

		// Stores the timeout as a duration
		duration := time.Duration(timeout) * time.Second

		// Builds a result slot for each port and protocol, so the output keeps the order given
		results := make([]grabResult, len(portList)*len(protocols))
		var wg sync.WaitGroup

		// Grabs every port and protocol at the same time
		index := 0
		for _, port := range portList {
			for _, protocol := range protocols {
				wg.Add(1)
				go func(i int, port string, protocol string) {
					defer wg.Done()
					results[i] = grabOne(target, port, protocol, duration)
				}(index, port, protocol)
				index++
			}
		}
		wg.Wait()

		// Outputs the header
		fmt.Printf("Grabbing banners from %s (%s)\n\n", target, strings.Join(protocols, ", "))

		// Outputs each of the results
		for _, r := range results {
			printGrabResult(r)
		}
	},
}

func init() {
	grabCmd.Flags().StringVarP(&target, "target", "t", "", "Domain to be targeted")
	grabCmd.Flags().StringVarP(&ports, "ports", "p", "", "Port(s) to be targeted, comma separated")

	// Adds the protocol flag to the grab command
	grabCmd.Flags().StringVar(&grabProtocol, "protocol", "tcp", "Protocol to use: tcp, udp or both")

	// Adds the command to the root command
	rootCmd.AddCommand(grabCmd)
}