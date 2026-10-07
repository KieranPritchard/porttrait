package fingerprinting

import (
	"fmt"
	"regexp"
)

// Stores the UDP probes, most specific rule first within each probe
var UDPProbes = []UDPProbe{
	{
		Name:  "dns-version-bind",
		Ports: []int{53},
		// CHAOS TXT query for version.bind
		Payload: []byte("\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03"),
		Rules: []UDPRule{
			{
				// Answer with a version string, which is also passed to Recog
				Pattern: regexp.MustCompile(`\xc0\x0c\x00\x10\x00\x03[\x00-\xff]{4}[\x00-\xff]{2}[\x00-\xff]([\x20-\x7e]+)`),
				Product: "DNS server", Version: "",
				Recog: "dns_versionbind.xml",
			},
			{
				// Any response with the QR (response) bit set
				Pattern: regexp.MustCompile(`^[\x00-\xff]{2}[\x80-\xff]`),
				Product: "DNS server",
			},
		},
	},
	{
		Name:  "dns-root-query",
		Ports: []int{53},
		// Standard DNS NS query for root "."
		Payload: []byte("\x10\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01"),
		Rules: []UDPRule{
			{
				// Any response with the QR bit set
				Pattern: regexp.MustCompile(`^[\x00-\xff]{2}[\x80-\xff]`),
				Product: "DNS server",
			},
		},
	},
	{
		Name:    "ntp-mode6-readvar",
		Ports:   []int{123},
		// NTP mode 6 (Control Message), Opcode 2 (Read Variables)
		Payload: []byte("\x16\x02\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"),
		Rules: []UDPRule{
			{
				// Matches NTP mode 6 response and extracts the variable payload into capture group 1 for Recog
				Pattern: regexp.MustCompile(`^[\x00-\xff]{12}([\x20-\x7e\r\n\t]+)`),
				Product: "NTP server",
				Recog:   "ntp_banners.xml",
			},
			{
				// Any NTP mode 6 response
				Pattern: regexp.MustCompile(`^\x16[\x80-\x8f]`),
				Product: "NTP server",
			},
		},
	},
	{
		Name:    "ntp-client",
		Ports:   []int{123},
		Payload: ntpProbe(),
		Rules: []UDPRule{
			{
				Func: func(resp []byte) *MatchResult {
					// Needs a full packet in server mode (4)
					if len(resp) < 48 || resp[0]&0x07 != 4 {
						return nil
					}
					version := (resp[0] >> 3) & 0x07
					return &MatchResult{Product: "NTP server", Version: fmt.Sprintf("v%d", version)}
				},
			},
		},
	},
	{
		Name:  "snmp-v1-public",
		Ports: []int{161},
		// GetRequest for sysDescr.0 with the community "public"
		Payload: []byte("\x30\x29\x02\x01\x00\x04\x06public\xa0\x1c\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"),
		Rules: []UDPRule{
			{
				// GetResponse containing the sysDescr string, also passed to Recog
				Pattern: regexp.MustCompile(`\x04\x06public\xa2[\x00-\xff]*?\x2b\x06\x01\x02\x01\x01\x01\x00\x04(?:[\x00-\x7f]|\x81[\x00-\xff]|\x82[\x00-\xff]{2})([\x20-\x7e]+)`),
				Product: "SNMP agent", Version: "v1",
				Recog: "snmp_sysdescr.xml",
			},
			{
				// Any GetResponse (e.g. an error response)
				Pattern: regexp.MustCompile(`^\x30[\x00-\xff]*\xa2`),
				Product: "SNMP agent",
			},
		},
	},
	{
		Name:    "netbios-node-status",
		Ports:   []int{137},
		Payload: netbiosProbe(),
		Rules: []UDPRule{
			{
				Pattern: regexp.MustCompile(`^\x80\xf0`),
				Product: "NetBIOS Name Service",
			},
		},
	},
	{
		Name:  "ssdp-msearch",
		Ports: []int{1900},
		Payload: []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n" +
			"MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"),
		Rules: []UDPRule{
			{
				// The SERVER header is kept in the product name
				Pattern: regexp.MustCompile(`(?is)^HTTP/1\.[01] 200.*?\r\nserver:\s*([^\r\n]+)`),
				Product: "UPnP ($1)",
				Recog:   "http_servers.xml",
			},
			{
				Pattern: regexp.MustCompile(`(?i)^HTTP/1\.[01] 200`),
				Product: "UPnP",
			},
		},
	},
	{
		Name:  "sip-options",
		Ports: []int{5060},
		// SIP OPTIONS request to probe SIP proxies/endpoints
		Payload: []byte("OPTIONS sip:nm SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP nm:5060;branch=z9hG4bK.1;rport\r\n" +
			"From: <sip:nm@nm>;tag=1\r\n" +
			"To: <sip:nm@nm>\r\n" +
			"Call-ID: 1@nm\r\n" +
			"CSeq: 1 OPTIONS\r\n" +
			"Max-Forwards: 70\r\n" +
			"Content-Length: 0\r\n\r\n"),
		Rules: []UDPRule{
			{
				// Server or User-Agent header passed to recog sip_banners.xml
				Pattern: regexp.MustCompile(`(?is)^SIP/2\.0\s+\d{3}.*?\r\n(?:Server|User-Agent):\s*([^\r\n]+)`),
				Product: "SIP ($1)",
				Recog:   "sip_banners.xml",
			},
			{
				// Any SIP response status line
				Pattern: regexp.MustCompile(`(?i)^SIP/2\.0\s+\d{3}`),
				Product: "SIP server",
			},
		},
	},
	{
		Name:  "tftp-rrq",
		Ports: []int{69},
		// TFTP Read Request (RRQ) for test.txt in octet mode
		Payload: []byte("\x00\x01test.txt\x00octet\x00"),
		Rules: []UDPRule{
			{
				// Opcode 5 (Error), captures error message string
				Pattern: regexp.MustCompile(`^\x00\x05[\x00-\xff]{2}([\x20-\x7e]+)`),
				Product: "TFTP server",
				Version: "$1",
			},
			{
				// Any TFTP error packet
				Pattern: regexp.MustCompile(`^\x00\x05`),
				Product: "TFTP server",
			},
		},
	},
	{
		Name:  "mssql-ssrp",
		Ports: []int{1434},
		// SQL Server Resolution Protocol (SSRP) CLNT_BCAST_EX request
		Payload: []byte{0x02},
		Rules: []UDPRule{
			{
				// Response contains ServerName;...;Version;10.0.1600.22;...
				Pattern: regexp.MustCompile(`(?i)^\x05[\x00-\xff]{2}.*?Version;([^;]+)`),
				Vendor:  "Microsoft",
				Product: "SQL Server (SSRP)",
				Version: "$1",
			},
			{
				// Any SSRP response starting with SVR_RESP (0x05)
				Pattern: regexp.MustCompile(`^\x05[\x00-\xff]{2}ServerName;`),
				Vendor:  "Microsoft",
				Product: "SQL Server (SSRP)",
			},
		},
	},
	{
		Name:  "memcached-version",
		Ports: []int{11211},
		// 8-byte UDP request header + "version\r\n"
		Payload: []byte("\x00\x00\x00\x00\x00\x01\x00\x00version\r\n"),
		Rules: []UDPRule{
			{
				Pattern: regexp.MustCompile(`^[\x00-\xff]{8}VERSION\s+([0-9\.]+)`),
				Vendor:  "Memcached",
				Product: "Memcached",
				Version: "$1",
			},
			{
				Pattern: regexp.MustCompile(`^[\x00-\xff]{8}VERSION`),
				Vendor:  "Memcached",
				Product: "Memcached",
			},
		},
	},
	{
		Name:  "mdns-query",
		Ports: []int{5353},
		// DNS PTR query for _services._dns-sd._udp.local
		Payload: []byte("\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01"),
		Rules: []UDPRule{
			{
				// DNS response with QR bit set
				Pattern: regexp.MustCompile(`^[\x00-\xff]{2}[\x80-\xff]`),
				Product: "mDNS / Bonjour",
			},
		},
	},
	{
		Name:  "openvpn-reset",
		Ports: []int{1194},
		// P_CONTROL_HARD_RESET_CLIENT_V2
		Payload: []byte("\x38\x01\x00\x00\x00\x00\x00\x00\x00"),
		Rules: []UDPRule{
			{
				// Server responds with P_CONTROL_HARD_RESET_SERVER_V2 (opcode 0x40)
				Pattern: regexp.MustCompile(`^\x40`),
				Product: "OpenVPN",
			},
		},
	},
	{
		Name:  "ipmi-rmcp-ping",
		Ports: []int{623},
		// RMCP Presence Ping
		Payload: []byte("\x06\x00\xff\x06\x00\x00\x11\xbe\x80\x00\x00\x00"),
		Rules: []UDPRule{
			{
				// RMCP Presence Pong with ASF IANA enterprise number (0x000011be)
				Pattern: regexp.MustCompile(`^\x06\x00[\x00-\xff]\x06\x00\x00\x11\xbe\x40`),
				Product: "IPMI RMCP",
			},
		},
	},
	{
		Name:    "dhcp-discover",
		Ports:   []int{67},
		Payload: dhcpProbe(),
		Rules: []UDPRule{
			{
				// Boot reply (op=2)
				Pattern: regexp.MustCompile(`^\x02\x01\x06`),
				Product: "DHCP server",
			},
		},
	},
}