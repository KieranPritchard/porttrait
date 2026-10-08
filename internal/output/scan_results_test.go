package output

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"kpritchard.co.uk/porttrait/internal/fingerprinting"
)

func TestShortBanner(t *testing.T) {
	tests := []struct {
		name     string
		banner   string
		max      int
		expected string
	}{
		{
			name:     "empty banner",
			banner:   "",
			max:      50,
			expected: "-",
		},
		{
			name:     "whitespace only",
			banner:   "   \n  \r\n  ",
			max:      50,
			expected: "-",
		},
		{
			name:     "short single line",
			banner:   "SSH-2.0-OpenSSH_8.9p1",
			max:      50,
			expected: "SSH-2.0-OpenSSH_8.9p1",
		},
		{
			name:     "multiline takes first line only",
			banner:   "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: Apache",
			max:      50,
			expected: "HTTP/1.1 200 OK",
		},
		{
			name:     "long banner truncated with ellipsis",
			banner:   "This is a very long banner that definitely exceeds the specified max limit",
			max:      20,
			expected: "This is a very lo...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shortBanner(tt.banner, tt.max)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestDescribeMatches(t *testing.T) {
	tests := []struct {
		name            string
		matches         []fingerprinting.MatchResult
		expectedService string
		expectedVersion string
	}{
		{
			name:            "empty matches",
			matches:         nil,
			expectedService: "-",
			expectedVersion: "-",
		},
		{
			name: "single match with version",
			matches: []fingerprinting.MatchResult{
				{Vendor: "OpenSSH", Product: "Server", Version: "8.9p1"},
			},
			expectedService: "OpenSSH Server",
			expectedVersion: "8.9p1",
		},
		{
			name: "single match without version",
			matches: []fingerprinting.MatchResult{
				{Vendor: "Apache", Product: "HTTP Server", Version: ""},
			},
			expectedService: "Apache HTTP Server",
			expectedVersion: "-",
		},
		{
			name: "multiple matches",
			matches: []fingerprinting.MatchResult{
				{Vendor: "Apache", Product: "HTTP Server", Version: "2.4.52"},
				{Vendor: "Ubuntu", Product: "Linux", Version: ""},
				{Vendor: "OpenSSL", Product: "OpenSSL", Version: "3.0.2"},
			},
			expectedService: "Apache HTTP Server (+2)",
			expectedVersion: "2.4.52",
		},
		{
			name: "match with blank vendor and product",
			matches: []fingerprinting.MatchResult{
				{Vendor: "", Product: "", Version: "1.0"},
			},
			expectedService: "-",
			expectedVersion: "1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, ver := describeMatches(tt.matches)
			if svc != tt.expectedService {
				t.Errorf("expected service %q, got %q", tt.expectedService, svc)
			}
			if ver != tt.expectedVersion {
				t.Errorf("expected version %q, got %q", tt.expectedVersion, ver)
			}
		})
	}
}

// captureStdout redirects os.Stdout and returns a function to restore it and get the output string
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	outChan := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outChan <- buf.String()
	}()

	fn()

	_ = w.Close()
	os.Stdout = oldStdout
	out := <-outChan
	_ = r.Close()
	return out
}

func TestPrintResults(t *testing.T) {
	results := []ScanResult{
		{
			Port:     "80",
			Protocol: "tcp",
			State:    "open",
			Banner:   "HTTP/1.1 200 OK\r\nServer: nginx\r\n",
			Matches: []fingerprinting.MatchResult{
				{Vendor: "Nginx", Product: "Web Server", Version: "1.18.0"},
			},
		},
		{
			Port:     "53",
			Protocol: "udp",
			State:    "open",
			Banner:   "DNS",
			Matches:  nil,
		},
	}

	output := captureStdout(t, func() {
		PrintResults(results)
	})

	if !strings.Contains(output, "PORT") || !strings.Contains(output, "STATE") || !strings.Contains(output, "SERVICE") {
		t.Errorf("expected table header in output, got:\n%s", output)
	}
	if !strings.Contains(output, "80/tcp") || !strings.Contains(output, "Nginx Web Server") {
		t.Errorf("expected port 80/tcp row in output, got:\n%s", output)
	}
	if !strings.Contains(output, "53/udp") || !strings.Contains(output, "open") {
		t.Errorf("expected port 53/udp row in output, got:\n%s", output)
	}
}

func TestPrintVerbose(t *testing.T) {
	results := []ScanResult{
		{
			Port:     "22",
			Protocol: "tcp",
			State:    "open",
			Banner:   "SSH-2.0-OpenSSH_8.9p1\nExtra info",
			Matches: []fingerprinting.MatchResult{
				{Vendor: "OpenSSH", Product: "Server", Version: "8.9p1"},
			},
		},
		{
			Port:     "123",
			Protocol: "udp",
			State:    "open|filtered",
			Banner:   "",
			Matches:  nil,
		},
	}

	output := captureStdout(t, func() {
		PrintVerbose(results)
	})

	if !strings.Contains(output, "--- 22/tcp ---") {
		t.Errorf("expected header for 22/tcp in output, got:\n%s", output)
	}
	if !strings.Contains(output, "SSH-2.0-OpenSSH_8.9p1") {
		t.Errorf("expected banner line in output, got:\n%s", output)
	}
	if !strings.Contains(output, "match: OpenSSH Server 8.9p1") {
		t.Errorf("expected match details in output, got:\n%s", output)
	}
	if !strings.Contains(output, "--- 123/udp ---") || !strings.Contains(output, "(no banner)") {
		t.Errorf("expected (no banner) for silent port in output, got:\n%s", output)
	}
}
