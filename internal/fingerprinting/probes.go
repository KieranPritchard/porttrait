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
			},
			{
				Pattern: regexp.MustCompile(`(?i)^HTTP/1\.[01] 200`),
				Product: "UPnP",
			},
		},
	},
}