package fingerprinting

import (
	"strings"
	"testing"
)

func TestLoadAllPrints(t *testing.T) {
	dbs, err := LoadAllPrints()
	if err != nil {
		t.Fatalf("unexpected error loading fingerprints: %v", err)
	}
	if len(dbs) < 19 {
		t.Errorf("expected at least 19 databases loaded, got %d", len(dbs))
	}

	// Verify crucial databases are present
	crucial := []string{
		"http_servers.xml",
		"ssh_banners.xml",
		"ftp_banners.xml",
		"smtp_banners.xml",
		"dns_versionbind.xml",
		"ntp_banners.xml",
		"sip_banners.xml",
		"snmp_sysdescr.xml",
		"mysql_banners.xml",
	}
	for _, name := range crucial {
		if _, ok := dbs[name]; !ok {
			t.Errorf("expected database %q to be loaded", name)
		}
	}

	// Verify caching on second call
	cachedDbs, err := LoadAllPrints()
	if err != nil {
		t.Fatalf("unexpected error loading cached fingerprints: %v", err)
	}
	if len(cachedDbs) != len(dbs) {
		t.Errorf("cached databases count mismatch: %d vs %d", len(cachedDbs), len(dbs))
	}
}

func TestMySQLHelpers(t *testing.T) {
	t.Run("isMySQLGreeting", func(t *testing.T) {
		// Valid MySQL greeting: 4 bytes length/seq, 0x0a (protocol 10), "5.7.42-log\x00"
		validGreeting := "\x4a\x00\x00\x00\x0a5.7.42-log\x00\x01\x02\x03"
		if !isMySQLGreeting(validGreeting) {
			t.Error("expected validGreeting to be recognized as MySQL")
		}

		// Cleaned dotted version without leading packet length
		dottedGreeting := "5.7.42-log ready"
		if !isMySQLGreeting(dottedGreeting) {
			t.Error("expected dottedGreeting to be recognized as MySQL")
		}

		// Non-MySQL strings
		if isMySQLGreeting("SSH-2.0-OpenSSH") {
			t.Error("SSH banner should not be recognized as MySQL")
		}
		if isMySQLGreeting("short") {
			t.Error("short non-MySQL string should not be recognized as MySQL")
		}
		if isMySQLGreeting("") {
			t.Error("empty string should not be recognized as MySQL")
		}
	})

	t.Run("extractMySQLVersion", func(t *testing.T) {
		validGreeting := "\x4a\x00\x00\x00\x0a8.0.32-Ubuntu\x00extra data"
		ver := extractMySQLVersion(validGreeting)
		if ver != "8.0.32-Ubuntu" {
			t.Errorf("expected version 8.0.32-Ubuntu, got %q", ver)
		}

		rawVersion := "8.0.28\x00extra"
		ver2 := extractMySQLVersion(rawVersion)
		if ver2 != "8.0.28" {
			t.Errorf("expected 8.0.28, got %q", ver2)
		}

		// Empty string
		if extractMySQLVersion("") != "" {
			t.Error("expected empty string for empty input")
		}
	})
}

func TestHTTPParsingHelpers(t *testing.T) {
	t.Run("httpBody", func(t *testing.T) {
		bannerCRLF := "HTTP/1.1 200 OK\r\nServer: test\r\n\r\n<html>Hello</html>"
		if httpBody(bannerCRLF) != "<html>Hello</html>" {
			t.Errorf("expected body with CRLF, got %q", httpBody(bannerCRLF))
		}

		bannerLF := "HTTP/1.1 200 OK\nServer: test\n\n<html>Hello LF</html>"
		if httpBody(bannerLF) != "<html>Hello LF</html>" {
			t.Errorf("expected body with LF, got %q", httpBody(bannerLF))
		}

		bannerNoBody := "HTTP/1.1 200 OK\r\nServer: test"
		if httpBody(bannerNoBody) != "" {
			t.Errorf("expected empty body when no delimiter, got %q", httpBody(bannerNoBody))
		}
	})

	t.Run("httpHeaderValues", func(t *testing.T) {
		banner := "HTTP/1.1 200 OK\r\n" +
			"Server: Apache/2.4.52 (Ubuntu)\r\n" +
			"X-Powered-By: PHP/8.1\r\n" +
			"Set-Cookie: session=123; path=/\r\n" +
			"Set-Cookie: token=abc; Secure\r\n\r\n"

		cookies := httpHeaderValues(banner, "Set-Cookie")
		if len(cookies) != 2 {
			t.Fatalf("expected 2 Set-Cookie headers, got %d", len(cookies))
		}
		if cookies[0] != "session=123; path=/" || cookies[1] != "token=abc; Secure" {
			t.Errorf("unexpected cookie values: %v", cookies)
		}

		server := httpHeaderValues(banner, "server") // case-insensitive check
		if len(server) != 1 || !strings.Contains(server[0], "Apache") {
			t.Errorf("expected Apache server header, got %v", server)
		}

		nonExistent := httpHeaderValues(banner, "Authorization")
		if len(nonExistent) != 0 {
			t.Errorf("expected empty slice for non-existent header, got %v", nonExistent)
		}
	})

	t.Run("httpStatusText", func(t *testing.T) {
		if httpStatusText("HTTP/1.1 200 OK") != "200 OK" {
			t.Errorf("expected '200 OK', got %q", httpStatusText("HTTP/1.1 200 OK"))
		}
		if httpStatusText("HTTP/1.0 404 Not Found") != "404 Not Found" {
			t.Errorf("expected '404 Not Found', got %q", httpStatusText("HTTP/1.0 404 Not Found"))
		}
		if httpStatusText("INVALID") != "" {
			t.Errorf("expected empty for invalid first line, got %q", httpStatusText("INVALID"))
		}
	})

	t.Run("extractServerHeader", func(t *testing.T) {
		banner := "HTTP/1.1 200 OK\r\nServer: nginx/1.22.0\r\n\r\n"
		server := extractServerHeader(banner)
		if server != "nginx/1.22.0" {
			t.Errorf("expected 'nginx/1.22.0', got %q", server)
		}

		noServer := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
		if extractServerHeader(noServer) != "" {
			t.Errorf("expected empty server header, got %q", extractServerHeader(noServer))
		}
	})
}

func TestAddMatchInput(t *testing.T) {
	inputs := make(map[string][]string)

	addMatchInput(inputs, "test.xml", "input1")
	addMatchInput(inputs, "test.xml", "input1") // duplicate should not be added
	addMatchInput(inputs, "test.xml", "  ")     // empty should not be added
	addMatchInput(inputs, "test.xml", "input2")

	if len(inputs["test.xml"]) != 2 {
		t.Fatalf("expected 2 inputs for test.xml, got %d", len(inputs["test.xml"]))
	}
	if inputs["test.xml"][0] != "input1" || inputs["test.xml"][1] != "input2" {
		t.Errorf("unexpected inputs: %v", inputs["test.xml"])
	}
}
