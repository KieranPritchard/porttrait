package fingerprinting

import (
	"testing"
)

func TestUDPProbesFor(t *testing.T) {
	tests := []struct {
		port          string
		expectedCount int
		expectedNames []string
	}{
		{
			port:          "53",
			expectedCount: 2,
			expectedNames: []string{"dns-version-bind", "dns-root-query"},
		},
		{
			port:          "123",
			expectedCount: 2,
			expectedNames: []string{"ntp-mode6-readvar", "ntp-client"},
		},
		{
			port:          "161",
			expectedCount: 1,
			expectedNames: []string{"snmp-v1-public"},
		},
		{
			port:          "137",
			expectedCount: 1,
			expectedNames: []string{"netbios-node-status"},
		},
		{
			port:          "1900",
			expectedCount: 1,
			expectedNames: []string{"ssdp-msearch"},
		},
		{
			port:          "5060",
			expectedCount: 1,
			expectedNames: []string{"sip-options"},
		},
		{
			port:          "69",
			expectedCount: 1,
			expectedNames: []string{"tftp-rrq"},
		},
		{
			port:          "1434",
			expectedCount: 1,
			expectedNames: []string{"mssql-ssrp"},
		},
		{
			port:          "11211",
			expectedCount: 1,
			expectedNames: []string{"memcached-version"},
		},
		{
			port:          "5353",
			expectedCount: 1,
			expectedNames: []string{"mdns-query"},
		},
		{
			port:          "1194",
			expectedCount: 1,
			expectedNames: []string{"openvpn-reset"},
		},
		{
			port:          "623",
			expectedCount: 1,
			expectedNames: []string{"ipmi-rmcp-ping"},
		},
		{
			port:          "67",
			expectedCount: 1,
			expectedNames: []string{"dhcp-discover"},
		},
		{
			port:          "9999",
			expectedCount: 1,
			expectedNames: []string{"generic"},
		},
		{
			port:          "invalid",
			expectedCount: 1,
			expectedNames: []string{"generic"},
		},
	}

	for _, tt := range tests {
		t.Run("Port_"+tt.port, func(t *testing.T) {
			probes := UDPProbesFor(tt.port)
			if len(probes) != tt.expectedCount {
				t.Fatalf("port %s expected %d probes, got %d", tt.port, tt.expectedCount, len(probes))
			}
			for i, expName := range tt.expectedNames {
				if probes[i].Name != expName {
					t.Errorf("probe %d expected name %s, got %s", i, expName, probes[i].Name)
				}
			}
		})
	}
}

func TestMatchUDP(t *testing.T) {
	t.Run("DNS_version_bind", func(t *testing.T) {
		probes := UDPProbesFor("53")
		// Response with CHAOS TXT payload for BIND
		resp := []byte("\x13\x37\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" +
			"\x07version\x04bind\x00\x00\x10\x00\x03" +
			"\xc0\x0c\x00\x10\x00\x03\x00\x00\x00\x00\x00\x0c" +
			"9.16.1-Ubuntu")
		matches := MatchUDP(probes[0], resp)
		if len(matches) == 0 {
			t.Fatal("expected matches for DNS version.bind, got none")
		}
		found := false
		for _, m := range matches {
			if m.Product == "BIND" || m.Product == "DNS server" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected BIND or DNS server in matches, got: %+v", matches)
		}
	})

	t.Run("NTP_mode6_readvar_recog", func(t *testing.T) {
		probes := UDPProbesFor("123")
		// 12-byte header + ntpd version string
		header := []byte("\x16\x82\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00")
		body := []byte("version=\"ntpd 4.2.8p15@1.3728-o (1)\", processor=\"x86_64\", system=\"Linux/5.4.0\"")
		resp := append(header, body...)

		matches := MatchUDP(probes[0], resp)
		if len(matches) == 0 {
			t.Fatal("expected matches for NTP mode 6 readvar, got none")
		}
		found := false
		for _, m := range matches {
			if m.Product == "NTP server" || m.Product == "ntpd" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected NTP match, got %+v", matches)
		}
	})

	t.Run("NTP_mode3_client", func(t *testing.T) {
		probes := UDPProbesFor("123")
		// Standard NTP packet with server mode 4 (lower 3 bits = 4) and version 4 (bits 3..5 = 4)
		resp := make([]byte, 48)
		resp[0] = (4 << 3) | 4 // VN=4, Mode=4
		matches := MatchUDP(probes[1], resp)
		if len(matches) != 1 || matches[0].Product != "NTP server" || matches[0].Version != "v4" {
			t.Fatalf("expected NTP server v4, got %+v", matches)
		}
	})

	t.Run("SIP_options_recog", func(t *testing.T) {
		probes := UDPProbesFor("5060")
		resp := []byte("SIP/2.0 200 OK\r\n" +
			"Via: SIP/2.0/UDP 10.0.0.1:5060\r\n" +
			"Server: Cisco-SIPGateway/IOS-12.x\r\n" +
			"Content-Length: 0\r\n\r\n")

		matches := MatchUDP(probes[0], resp)
		if len(matches) == 0 {
			t.Fatal("expected matches for SIP options response, got none")
		}
		foundCisco := false
		for _, m := range matches {
			if m.Vendor == "Cisco" || m.Product == "IOS" {
				foundCisco = true
				break
			}
		}
		if !foundCisco {
			t.Errorf("expected Cisco IOS match from sip_banners.xml, got %+v", matches)
		}
	})

	t.Run("TFTP_error", func(t *testing.T) {
		probes := UDPProbesFor("69")
		// Opcode 5, error code 1, error message "File not found\x00"
		resp := []byte("\x00\x05\x00\x01File not found\x00")
		matches := MatchUDP(probes[0], resp)
		if len(matches) == 0 {
			t.Fatal("expected matches for TFTP error, got none")
		}
		if matches[0].Product != "TFTP server" {
			t.Errorf("expected TFTP server product, got %s", matches[0].Product)
		}
	})

	t.Run("MSSQL_SSRP", func(t *testing.T) {
		probes := UDPProbesFor("1434")
		body := "ServerName;SQL01;InstanceName;MSSQLSERVER;IsClustered;No;Version;15.0.2000.5;tcp;1433;;"
		resp := append([]byte{0x05, 0x00, byte(len(body))}, []byte(body)...)
		matches := MatchUDP(probes[0], resp)
		if len(matches) == 0 {
			t.Fatal("expected matches for MSSQL SSRP, got none")
		}
		if matches[0].Product != "SQL Server (SSRP)" || matches[0].Version != "15.0.2000.5" {
			t.Errorf("expected SQL Server (SSRP) version 15.0.2000.5, got %+v", matches[0])
		}
	})

	t.Run("Memcached_version", func(t *testing.T) {
		probes := UDPProbesFor("11211")
		resp := []byte("\x00\x00\x00\x00\x00\x01\x00\x00VERSION 1.6.9\r\n")
		matches := MatchUDP(probes[0], resp)
		if len(matches) == 0 {
			t.Fatal("expected matches for Memcached, got none")
		}
		if matches[0].Product != "Memcached" || matches[0].Version != "1.6.9" {
			t.Errorf("expected Memcached version 1.6.9, got %+v", matches[0])
		}
	})

	t.Run("OpenVPN_reset", func(t *testing.T) {
		probes := UDPProbesFor("1194")
		resp := []byte("\x40\x00\x00\x00\x00\x00\x00\x00\x01")
		matches := MatchUDP(probes[0], resp)
		if len(matches) == 0 || matches[0].Product != "OpenVPN" {
			t.Fatalf("expected OpenVPN match, got %+v", matches)
		}
	})

	t.Run("IPMI_RMCP", func(t *testing.T) {
		probes := UDPProbesFor("623")
		resp := []byte("\x06\x00\xff\x06\x00\x00\x11\xbe\x40\x00\x00\x00")
		matches := MatchUDP(probes[0], resp)
		if len(matches) == 0 || matches[0].Product != "IPMI RMCP" {
			t.Fatalf("expected IPMI RMCP match, got %+v", matches)
		}
	})

	t.Run("DHCP_discover", func(t *testing.T) {
		probes := UDPProbesFor("67")
		resp := []byte("\x02\x01\x06\x00")
		matches := MatchUDP(probes[0], resp)
		if len(matches) == 0 || matches[0].Product != "DHCP server" {
			t.Fatalf("expected DHCP server match, got %+v", matches)
		}
	})

	t.Run("Generic_probe_fallback", func(t *testing.T) {
		generic := UDPProbesFor("99999")[0]
		sipResp := []byte("SIP/2.0 200 OK\r\nServer: Asterisk PBX\r\n\r\n")
		matches := MatchUDP(generic, sipResp)
		if len(matches) == 0 {
			t.Fatal("expected generic probe to match SIP response, got none")
		}
		found := false
		for _, m := range matches {
			if m.Product == "PBX" || m.Product == "SIP (Asterisk PBX)" || m.Product == "SIP server" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("unexpected matches: %+v", matches)
		}
	})
}
