package input

import (
	"errors"
	"net/netip"
	"strings"
)

// Function to clean and prepare ip addresses
func PrepareIP(ip string) (string, error)  {
	if ip == "" {
		return "", errors.New("IP address cannot be empty")
	}
	
	// Removes write space and lowes the string
	ip = strings.TrimSpace(ip)

	// Parses the IP address and checks for errors
	address, err := netip.ParseAddr(ip)
	if err != nil {
		return "", err
	}

	// Checks if the address is valid
	if !address.IsValid() {
		return "", errors.New("IP address is not valid")
	}

	// Returns the IP address
	return ip, nil
}