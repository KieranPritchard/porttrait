package input

import (
	"strings"
	"testing"
)

func TestPreparePort(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{name: "standard port 80", input: "80", expected: "80", expectError: false},
		{name: "port with whitespace", input: "  443  ", expected: "443", expectError: false},
		{name: "lowest port 1", input: "1", expected: "1", expectError: false},
		{name: "highest port 65535", input: "65535", expected: "65535", expectError: false},
		{name: "empty port", input: "", expected: "", expectError: true},
		{name: "whitespace only", input: "   ", expected: "", expectError: true},
		{name: "zero port", input: "0", expected: "", expectError: true},
		{name: "negative port", input: "-22", expected: "", expectError: true},
		{name: "too large port", input: "65536", expected: "", expectError: true},
		{name: "non-numeric port", input: "http", expected: "", expectError: true},
		{name: "float port", input: "80.5", expected: "", expectError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := PreparePort(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for input %q, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for input %q: %v", tt.input, err)
				}
				if res != tt.expected {
					t.Errorf("expected %q, got %q", tt.expected, res)
				}
			}
		})
	}
}

func TestPrepareIP(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{name: "standard IPv4", input: "127.0.0.1", expected: "127.0.0.1", expectError: false},
		{name: "IPv4 with whitespace", input: "  192.168.1.1  ", expected: "192.168.1.1", expectError: false},
		{name: "standard IPv6", input: "::1", expected: "::1", expectError: false},
		{name: "full IPv6", input: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", expected: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", expectError: false},
		{name: "empty IP", input: "", expected: "", expectError: true},
		{name: "whitespace only", input: "   ", expected: "", expectError: true},
		{name: "invalid octet IPv4", input: "256.0.0.1", expected: "", expectError: true},
		{name: "too few octets", input: "127.0.1", expected: "", expectError: true},
		{name: "too many octets", input: "1.2.3.4.5", expected: "", expectError: true},
		{name: "letters in IP", input: "192.168.1.abc", expected: "", expectError: true},
		{name: "domain name instead of IP", input: "example.com", expected: "", expectError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := PrepareIP(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for input %q, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for input %q: %v", tt.input, err)
				}
				if res != tt.expected {
					t.Errorf("expected %q, got %q", tt.expected, res)
				}
			}
		})
	}
}

func TestPrepareDomain(t *testing.T) {
	t.Run("empty domain", func(t *testing.T) {
		_, err := PrepareDomain("")
		if err == nil {
			t.Error("expected error for empty domain, got nil")
		}
	})

	t.Run("localhost lookup", func(t *testing.T) {
		ips, err := PrepareDomain("localhost")
		if err != nil {
			t.Fatalf("unexpected error for localhost: %v", err)
		}
		if len(ips) == 0 {
			t.Error("expected at least one IP for localhost")
		}
		found := false
		for _, ip := range ips {
			if ip == "127.0.0.1" || ip == "::1" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected 127.0.0.1 or ::1 in localhost IPs, got: %v", ips)
		}
	})

	t.Run("domain with protocol prefix", func(t *testing.T) {
		ips, err := PrepareDomain("http://localhost:8080/test")
		if err != nil {
			t.Fatalf("unexpected error for http://localhost: %v", err)
		}
		if len(ips) == 0 {
			t.Error("expected at least one IP")
		}
	})

	t.Run("domain with path and port without protocol", func(t *testing.T) {
		ips, err := PrepareDomain("localhost:8080/path?query=1")
		if err != nil {
			t.Fatalf("unexpected error for localhost with path/port: %v", err)
		}
		if len(ips) == 0 {
			t.Error("expected at least one IP")
		}
	})

	t.Run("domain with trailing dot", func(t *testing.T) {
		ips, err := PrepareDomain("localhost.")
		if err != nil {
			t.Fatalf("unexpected error for localhost.: %v", err)
		}
		if len(ips) == 0 {
			t.Error("expected at least one IP")
		}
	})

	t.Run("nonexistent domain", func(t *testing.T) {
		_, err := PrepareDomain("nonexistent-domain-that-does-not-exist-12345.test")
		if err == nil {
			t.Error("expected lookup error for nonexistent domain, got nil")
		}
	})

	t.Run("domain exceeding max length", func(t *testing.T) {
		tooLong := strings.Repeat("a", 254) + ".com"
		_, err := PrepareDomain(tooLong)
		if err == nil {
			t.Error("expected error for domain exceeding length, got nil")
		}
	})
}
