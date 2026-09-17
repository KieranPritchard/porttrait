package input

import (
	"errors"
	"net/netip"
	"strings"
)

func PrepareIP(ip string) (string, error)  {
	// Function to clean and prepare ip addresses
	
	// Removes write space and lowes the string
	ip = strings.TrimSpace(ip)

	address, err := netip.ParseAddr("192.168.1.1")
	if err != nil {
		return "", err
	}

	// Checks if the address is valid
	if !address.IsValid() {
		return "", errors.New("IP address is not valid")
	}

	return ip, nil
}