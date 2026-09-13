package bannergrabbing

import (
	"io"
	"net"
	"time"
)

// Helper function to grab a service banner
func GrabUDPBanner(target string, timeout time.Duration) (string, error) {
	// Attempts a tcp connection to target and closes when done
	conn, err := net.DialTimeout("udp", target, timeout)
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