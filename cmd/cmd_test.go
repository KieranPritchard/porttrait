package cmd

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseProtocols(t *testing.T) {
	tests := []struct {
		input       string
		expected    []string
		expectError bool
	}{
		{input: "tcp", expected: []string{"tcp"}, expectError: false},
		{input: "udp", expected: []string{"udp"}, expectError: false},
		{input: "both", expected: []string{"tcp", "udp"}, expectError: false},
		{input: "TCP", expected: []string{"tcp"}, expectError: false},
		{input: "UDP", expected: []string{"udp"}, expectError: false},
		{input: "BOTH", expected: []string{"tcp", "udp"}, expectError: false},
		{input: "invalid", expected: nil, expectError: true},
		{input: "", expected: nil, expectError: true},
	}

	for _, tt := range tests {
		t.Run("protocol_"+tt.input, func(t *testing.T) {
			res, err := parseProtocols(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for protocol %q, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for protocol %q: %v", tt.input, err)
				}
				if len(res) != len(tt.expected) {
					t.Fatalf("expected len %d, got %d", len(tt.expected), len(res))
				}
				for i, v := range tt.expected {
					if res[i] != v {
						t.Errorf("expected %q, got %q", v, res[i])
					}
				}
			}
		})
	}
}

func TestGrabOne(t *testing.T) {
	t.Run("TCP open service", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen on tcp: %v", err)
		}
		defer ln.Close()

		_, portStr, _ := net.SplitHostPort(ln.Addr().String())

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_8.9\r\n"))
		}()

		result := grabOne("127.0.0.1", portStr, "tcp", 500*time.Millisecond)
		if result.State != "open" {
			t.Errorf("expected state 'open', got %q", result.State)
		}
		if !strings.Contains(result.Banner, "SSH-2.0-OpenSSH_8.9") {
			t.Errorf("expected SSH banner, got %q", result.Banner)
		}
		if len(result.Matches) == 0 {
			t.Error("expected matches for OpenSSH banner, got none")
		}
	})

	t.Run("TCP closed port", func(t *testing.T) {
		// Use guaranteed closed port
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		_, portStr, _ := net.SplitHostPort(ln.Addr().String())
		_ = ln.Close()

		result := grabOne("127.0.0.1", portStr, "tcp", 200*time.Millisecond)
		if result.State != "closed" {
			t.Errorf("expected state 'closed', got %q", result.State)
		}
	})

	t.Run("UDP service grab", func(t *testing.T) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen on udp: %v", err)
		}
		defer pc.Close()

		_, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())

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

		result := grabOne("127.0.0.1", portStr, "udp", 500*time.Millisecond)
		if result.State != "open" {
			t.Errorf("expected state 'open', got %q", result.State)
		}
		if !strings.Contains(result.Banner, "SIP/2.0") {
			t.Errorf("expected SIP banner, got %q", result.Banner)
		}
	})
}

func TestCommandHierarchy(t *testing.T) {
	if rootCmd.Use != "porttrait" {
		t.Errorf("expected rootCmd use 'porttrait', got %q", rootCmd.Use)
	}

	commands := rootCmd.Commands()
	hasGrab := false
	hasScan := false
	for _, c := range commands {
		if c.Name() == "grab" {
			hasGrab = true
		}
		if c.Name() == "scan" {
			hasScan = true
		}
	}

	if !hasGrab {
		t.Error("expected rootCmd to have 'grab' subcommand")
	}
	if !hasScan {
		t.Error("expected rootCmd to have 'scan' subcommand")
	}

	// Check persistent flags
	if rootCmd.PersistentFlags().Lookup("timeout") == nil {
		t.Error("expected 'timeout' persistent flag on rootCmd")
	}
	if rootCmd.PersistentFlags().Lookup("target") == nil {
		t.Error("expected 'target' persistent flag on rootCmd")
	}
	if rootCmd.PersistentFlags().Lookup("ports") == nil {
		t.Error("expected 'ports' persistent flag on rootCmd")
	}
	if rootCmd.PersistentFlags().Lookup("protocol") == nil {
		t.Error("expected 'protocol' persistent flag on rootCmd")
	}

	// Check scan command flags
	if scanCmd.Flags().Lookup("protocol") == nil {
		t.Error("expected 'protocol' flag on scanCmd")
	}
	if scanCmd.Flags().Lookup("verbose") == nil {
		t.Error("expected 'verbose' flag on scanCmd")
	}
}
