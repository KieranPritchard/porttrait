package fingerprinting

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Stores a rule that recognises a service from a UDP response
type UDPRule struct {
	// Pattern is matched against the response (see toLatin1)
	Pattern *regexp.Regexp

	// Vendor, Product and Version can use $1, $2 etc. from the pattern
	Vendor  string
	Product string
	Version string

	// Optional: capture group 1 is also fed to this Recog database
	Recog string

	// Optional: used instead of Pattern for binary checks a regex can't do
	Func func(resp []byte) *MatchResult
}

// Stores a probe to send and the rules that recognise its responses
type UDPProbe struct {
	Name    string
	Ports   []int // empty means the probe is used for any port
	Payload []byte
	Rules   []UDPRule
}

// Turns every byte into the rune with the same value, so \xNN in a pattern
// matches the byte 0xNN (Go regexes work on UTF-8, which breaks binary matching)
func toLatin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

// Builds the NetBIOS node status request
func netbiosProbe() []byte {
	p := "\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20"
	p += "CK" + strings.Repeat("A", 30)
	p += "\x00\x00\x21\x00\x01"
	return []byte(p)
}

// Builds the NTP client request (version 3, mode 3)
func ntpProbe() []byte {
	p := make([]byte, 48)
	p[0] = 0x1b
	return p
}

// Stores the UDP probes, most specific rule first within each probe
var udpProbes = []UDPProbe{
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

// Used for any port that has no specific probe
var genericUDPProbe = UDPProbe{
	Name:    "generic",
	Payload: []byte{0x00},
}

// Returns the probes to send to a port
func UDPProbesFor(port string) []UDPProbe {
	p, err := strconv.Atoi(port)
	if err != nil {
		return []UDPProbe{genericUDPProbe}
	}

	var probes []UDPProbe
	for _, probe := range udpProbes {
		for _, candidate := range probe.Ports {
			if candidate == p {
				probes = append(probes, probe)
				break
			}
		}
	}

	// Falls back to the generic probe when nothing is specific to the port
	if len(probes) == 0 {
		return []UDPProbe{genericUDPProbe}
	}
	return probes
}

// Runs a Recog database against a string pulled out of a response
func recogMatches(dbFile string, input string) []MatchResult {
	dbs, err := LoadAllPrints()
	if err != nil {
		return nil
	}
	db, ok := dbs[dbFile]
	if !ok {
		return nil
	}

	var out []MatchResult
	for _, match := range db.MatchAll(input) {
		m := MatchResult{
			Vendor:  match.Values["service.vendor"],
			Product: match.Values["service.product"],
			Version: match.Values["service.version"],
		}
		if m.Vendor != "" || m.Product != "" || m.Version != "" {
			out = append(out, m)
		}
	}
	return out
}

// Matches a response to a probe against its rules (first matching rule wins)
func MatchUDP(probe UDPProbe, resp []byte) []MatchResult {
	s := toLatin1(resp)

	for _, rule := range probe.Rules {
		// Binary checks
		if rule.Func != nil {
			if m := rule.Func(resp); m != nil {
				return []MatchResult{*m}
			}
			continue
		}

		// Pattern checks
		idx := rule.Pattern.FindStringSubmatchIndex(s)
		if idx == nil {
			continue
		}

		var out []MatchResult

		// Recog matches come first because they are the most specific
		if rule.Recog != "" && len(idx) >= 4 && idx[2] >= 0 {
			out = append(out, recogMatches(rule.Recog, s[idx[2]:idx[3]])...)
		}

		// Expands $1 etc. in the rule's fields
		expand := func(t string) string {
			return string(rule.Pattern.ExpandString(nil, t, s, idx))
		}
		out = append(out, MatchResult{
			Vendor:  expand(rule.Vendor),
			Product: expand(rule.Product),
			Version: expand(rule.Version),
		})
		return out
	}

	return nil
}