package main

import (
	"fmt"
	"io"
	"net"
	"time"
)

// Helper function to grab a service banner
func grabBanner(target string, timeout time.Duration) (string, error) {
	// Attempts a tcp connection to target and closes when done
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Sets the deadline for reading data
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	// Stores the buffer
	buf := make([]byte, 1024)
	
	// Reads in the buffer
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return "", err
	}

	// Returns the string from the buffer
	return string(buf[:n]), nil
}

func main() {
	// Grabs the banner
	banner, err := grabBanner("scanme.nmap.org:22", 3*time.Second)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Outputs the banner
	fmt.Printf("Banner Output:\n%s", banner)
}