package banners

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

type mockTimeoutError struct{}

func (m mockTimeoutError) Error() string   { return "i/o timeout" }
func (m mockTimeoutError) Timeout() bool   { return true }
func (m mockTimeoutError) Temporary() bool { return true }

func TestIsTimeout(t *testing.T) {
	if !isTimeout(mockTimeoutError{}) {
		t.Error("expected mockTimeoutError to be recognized as timeout")
	}
	if isTimeout(errors.New("generic error")) {
		t.Error("expected generic error to not be recognized as timeout")
	}
	if isTimeout(nil) {
		t.Error("expected nil to not be recognized as timeout")
	}
}

func TestCleanBanner(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "plain text",
			input:    []byte("SSH-2.0-OpenSSH_8.9"),
			expected: "SSH-2.0-OpenSSH_8.9",
		},
		{
			name:     "text with newlines and tabs",
			input:    []byte("220 Welcome\r\n\tReady"),
			expected: "220 Welcome\r\n\tReady",
		},
		{
			name:     "control characters stripped",
			input:    []byte("\x00\x01\x02Hello\x07\x08World\x7f"),
			expected: "HelloWorld",
		},
		{
			name:     "invalid utf8 stripped",
			input:    []byte("Valid\xff\xfeString"),
			expected: "ValidString",
		},
		{
			name:     "whitespace trimmed",
			input:    []byte("   \r\n  Banner with spaces  \r\n  "),
			expected: "Banner with spaces",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanBanner(tt.input)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestGrabTCPBanners(t *testing.T) {
	t.Run("server speaks first", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to start mock TCP listener: %v", err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = conn.Write([]byte("SSH-2.0-MockSSH_Server\r\n"))
		}()

		banner, err := GrabTCPBanners(ln.Addr().String(), 500*time.Millisecond)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(banner, "SSH-2.0-MockSSH_Server") {
			t.Errorf("expected SSH banner, got %q", banner)
		}
	})

	t.Run("server speaks after probe", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to start mock TCP listener: %v", err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err == nil && n > 0 && strings.Contains(string(buf[:n]), "HEAD / HTTP") {
				_, _ = conn.Write([]byte("HTTP/1.0 200 OK\r\nServer: MockHTTP\r\n\r\n"))
			}
		}()

		banner, err := GrabTCPBanners(ln.Addr().String(), 500*time.Millisecond)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(banner, "MockHTTP") {
			t.Errorf("expected HTTP response, got %q", banner)
		}
	})

	t.Run("connection failure on closed port", func(t *testing.T) {
		// Pick an unused local port
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		addr := ln.Addr().String()
		_ = ln.Close() // immediately close to guarantee port is closed

		_, err = GrabTCPBanners(addr, 200*time.Millisecond)
		if err == nil {
			t.Error("expected connection error for closed port, got nil")
		}
	})
}

func TestGrabUDPRaw(t *testing.T) {
	t.Run("successful UDP echo", func(t *testing.T) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen on udp: %v", err)
		}
		defer pc.Close()

		go func() {
			buf := make([]byte, 1024)
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n > 0 {
				_, _ = pc.WriteTo([]byte("PONG:"+string(buf[:n])), addr)
			}
		}()

		resp, err := GrabUDPRaw(pc.LocalAddr().String(), []byte("PING"), 500*time.Millisecond)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(resp) != "PONG:PING" {
			t.Errorf("expected PONG:PING, got %q", string(resp))
		}
	})

	t.Run("UDP timeout returns ErrNoResponse", func(t *testing.T) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen on udp: %v", err)
		}
		defer pc.Close()
		// Silent server: reads nothing, responds to nothing

		_, err = GrabUDPRaw(pc.LocalAddr().String(), []byte("PING"), 100*time.Millisecond)
		if !errors.Is(err, ErrNoResponse) {
			t.Errorf("expected ErrNoResponse on timeout, got %v", err)
		}
	})
}

func TestGrabUDPBanners(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on udp: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 1024)
		_, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo([]byte("UDP Service Greeting\r\n"), addr)
	}()

	banner, err := GrabUDPBanners(pc.LocalAddr().String(), 500*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(banner, "UDP Service Greeting") {
		t.Errorf("expected UDP banner, got %q", banner)
	}
}
