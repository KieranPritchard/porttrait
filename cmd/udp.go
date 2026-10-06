package cmd

import (
	"errors"
	"net"
	"time"

	banners "kpritchard.co.uk/porttrait/internal/banners"
	"kpritchard.co.uk/porttrait/internal/fingerprinting"
)

// Replaces anything that isn't printable text with a dot
func printable(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if (c >= 32 && c < 127) || c == '\r' || c == '\n' || c == '\t' {
			out[i] = c
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}

// Probes a UDP port and returns the banner, matches and state
func scanUDP(target string, port string, timeout time.Duration) (string, []fingerprinting.MatchResult, string, error) {
	address := net.JoinHostPort(target, port)

	// Tries each probe for the port until one gets a reply
	for _, probe := range fingerprinting.UDPProbesFor(port) {
		resp, err := banners.GrabUDPRaw(address, probe.Payload, timeout)

		// No reply to this probe, so tries the next one
		if errors.Is(err, banners.ErrNoResponse) {
			continue
		}

		// Anything else (e.g. ICMP port unreachable) means closed
		if err != nil {
			return "", nil, "closed", err
		}

		return printable(resp), fingerprinting.MatchUDP(probe, resp), "open", nil
	}

	// Nothing replied to any probe
	return "", nil, "open|filtered", nil
}