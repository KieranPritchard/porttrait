package bannergrabbing

import (
	"errors"
	"net"
	"strings"
	"time"
)

// Returned for UDP when the service didn't reply (port is open or filtered)
var ErrNoResponse = errors.New("no response from service")

// Size of the buffer used to read banners
const bufferSize = 1024

// Probe sent to TCP services that wait for the client to speak first (e.g. HTTP)
const tcpProbe = "HEAD / HTTP/1.0\r\n\r\n"

// Checks if an error was caused by a timeout
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// Removes invalid and non-printable characters from the banner
func cleanBanner(b []byte) string {
	s := strings.ToValidUTF8(string(b), "")
	s = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' || (r >= 32 && r != 127) {
			return r
		}
		return -1
	}, s)
	return strings.TrimSpace(s)
}

// Reads from the connection and returns whatever was received
func readBanner(conn net.Conn, timeout time.Duration) (string, error) {
	// Sets the deadline for reading data
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}

	// Stores the buffer
	buf := make([]byte, bufferSize)

	// Reads in the buffer
	n, err := conn.Read(buf)

	// Keeps any data that arrived, even if an error came with it
	if n > 0 {
		return cleanBanner(buf[:n]), nil
	}

	return "", err
}

// Helper function to grab a TCP service banner
func GrabTCPBanners(target string, timeout time.Duration) (string, error) {
	// Attempts a tcp connection to target and closes when done
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		// Connection failed, so the port is closed or filtered
		return "", err
	}
	defer conn.Close()

	// Waits for the service to send its own banner (SSH, FTP, SMTP etc.)
	banner, _ := readBanner(conn, timeout)
	if banner != "" {
		return banner, nil
	}

	// Service stayed silent, so sends a probe to provoke a response (HTTP etc.)
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(tcpProbe)); err != nil {
		// The connection succeeded, so the port is still open
		return "", nil
	}

	// Reads the response to the probe
	banner, _ = readBanner(conn, timeout)

	// Open port, banner may be empty
	return banner, nil
}

// Helper function to grab a UDP service banner
func GrabUDPBanners(target string, timeout time.Duration) (string, error) {
	// Sets up the udp socket (no handshake happens here) and closes when done
	conn, err := net.DialTimeout("udp", target, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Sends a probe, since most UDP services never speak first
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{0x00}); err != nil {
		return "", err
	}

	// Reads the response
	banner, err := readBanner(conn, timeout)
	if banner != "" {
		return banner, nil
	}

	// Timeout means the port is open or filtered, so it is reported separately
	if isTimeout(err) {
		return "", ErrNoResponse
	}

	// Anything else (e.g. connection refused from ICMP unreachable) means closed
	return "", err
}