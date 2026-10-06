package input

import (
	"errors"
	"net"
	"net/url"
	"strings"
	"golang.org/x/net/idna"
)

// Cleans and validates the domain
func PrepareDomain(domain string) ([]string, error)  {
	if domain == "" {
		return nil, errors.New("domain cannot be empty")
	}
	
	// Removes write space and lowes the string
	domain = strings.TrimSpace(strings.ToLower(domain))

	// Remove common protocol prefixes if present
	if strings.Contains(domain, "://") {
		// Parses the domain and checks for errors
		targetDomain, err := url.Parse(domain)
		if err != nil  {
			return nil, err
		}

		// Returns the hostname
		domain = targetDomain.Hostname()
	} else {
		// Strip path, port, or query parameters if user passed "example.com/path" or "example.com:8080"
		idx := strings.IndexAny(domain, "/:?#")
		if idx == -1 {
			return nil, errors.New("Unable to strip domain from ports and protocol")
		}

		// Returns the domain
		domain = domain[:idx]
	}

	// Remove trailing dot (canonical form root domain)
	domain = strings.TrimSuffix(domain, ".")

	// Convert Internationalized Domain Names (IDN) to ASCII Punycode (e.g., "münchen.de" -> "xn--mnchen-3ya.de")
	p := idna.New()
	ascii, err := p.ToASCII(domain)
	if err != nil {
		return nil, err
	}

	domain = ascii

	// Checks if there is data entered
	if len(domain) == 0 || len(domain) > 253{
		return nil, errors.New("Domain cannot be empty")
	}

	// Gets the ip addresses
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, err
	}

	// Stores the targets
	targets := make([]string, 0)

	// Loops over each of the ip addresses
	for _, ip := range ips {
		// Gets the ip address
		ipv4 := ip.To4()
		
		// Checks if emptu
		if ipv4 == nil {
			return nil, errors.New("There is no IP address on this domain")
		}

		targets = append(targets, ipv4.String())
	}

	// Returns domain and nil error
	return targets, nil
}