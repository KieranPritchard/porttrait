package scan

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"kpritchard.co.uk/porttrait/internal/output"
)

func TestPrintable(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "all printable ascii",
			input:    []byte("Hello, World! 123"),
			expected: "Hello, World! 123",
		},
		{
			name:     "newlines and tabs preserved",
			input:    []byte("Line 1\r\n\tLine 2"),
			expected: "Line 1\r\n\tLine 2",
		},
		{
			name:     "binary replaced with dots",
			input:    []byte{0x00, 0x01, 'O', 'K', 0x7f, 0xff},
			expected: "..OK..",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := printable(tt.input)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestScanUDP(t *testing.T) {
	t.Run("open responsive UDP service", func(t *testing.T) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen on udp: %v", err)
		}
		defer pc.Close()

		_, portStr, err := net.SplitHostPort(pc.LocalAddr().String())
		if err != nil {
			t.Fatalf("failed to split host port: %v", err)
		}

		go func() {
			buf := make([]byte, 1024)
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n > 0 {
				_, _ = pc.WriteTo([]byte("SIP/2.0 200 OK\r\nServer: TestSIP\r\n\r\n"), addr)
			}
		}()

		banner, matches, state, err := ScanUDP("127.0.0.1", portStr, 500*time.Millisecond)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if state != "open" {
			t.Errorf("expected state 'open', got %q", state)
		}
		if !strings.Contains(banner, "SIP/2.0") {
			t.Errorf("expected SIP in banner, got %q", banner)
		}
		if len(matches) == 0 {
			t.Error("expected matches for SIP response, got none")
		}
	})

	t.Run("unresponsive UDP port returns open|filtered", func(t *testing.T) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen on udp: %v", err)
		}
		defer pc.Close()

		_, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())

		// Server does not reply
		banner, matches, state, err := ScanUDP("127.0.0.1", portStr, 100*time.Millisecond)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if state != "open|filtered" {
			t.Errorf("expected 'open|filtered', got %q", state)
		}
		if banner != "" || len(matches) > 0 {
			t.Errorf("expected empty banner and nil matches, got banner=%q matches=%+v", banner, matches)
		}
	})
}

func TestScanWorker(t *testing.T) {
	// Start a mock TCP server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock TCP listener: %v", err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("SSH-2.0-MockServer\r\n"))
			_ = conn.Close()
		}
	}()

	jobs := make(chan scanJob, 5)
	results := make(chan output.ScanResult, 5)
	var wg sync.WaitGroup

	wg.Add(1)
	go ScanWorker("127.0.0.1", 1, false, jobs, results, &wg)

	// Send an open port job and a closed port job
	jobs <- scanJob{Port: portStr, Protocol: "tcp"}
	jobs <- scanJob{Port: "59999", Protocol: "tcp"} // closed port
	close(jobs)

	wg.Wait()
	close(results)

	var collected []output.ScanResult
	for r := range results {
		collected = append(collected, r)
	}

	if len(collected) != 1 {
		t.Fatalf("expected 1 result (the open port), got %d", len(collected))
	}
	if collected[0].Port != portStr || collected[0].State != "open" {
		t.Errorf("unexpected result: %+v", collected[0])
	}
}

func TestRunScan(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock TCP listener: %v", err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("HTTP/1.0 200 OK\r\nServer: Nginx\r\n\r\n"))
			_ = conn.Close()
		}
	}()

	// Ensure RunScan executes without crashing or hanging
	port, _ := strconv.Atoi(portStr)
	RunScan("127.0.0.1", []string{strconv.Itoa(port)}, []string{"tcp"}, 1, true, false)
}
