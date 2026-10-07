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

// Used for any port that has no specific probe
var genericUDPProbe = UDPProbe{
	Name:    "generic",
	Payload: []byte{0x00},
	Rules: []UDPRule{
		{
			// SIP response with Server or User-Agent header
			Pattern: regexp.MustCompile(`(?is)^SIP/2\.0\s+\d{3}.*?\r\n(?:Server|User-Agent):\s*([^\r\n]+)`),
			Product: "SIP ($1)",
			Recog:   "sip_banners.xml",
		},
		{
			Pattern: regexp.MustCompile(`(?i)^SIP/2\.0\s+\d{3}`),
			Product: "SIP server",
		},
		{
			// HTTP response with Server header
			Pattern: regexp.MustCompile(`(?is)^HTTP/1\.[01]\s+\d{3}.*?\r\nserver:\s*([^\r\n]+)`),
			Product: "HTTP ($1)",
			Recog:   "http_servers.xml",
		},
		{
			Pattern: regexp.MustCompile(`(?i)^HTTP/1\.[01]\s+\d{3}`),
			Product: "HTTP server",
		},
		{
			// DNS response with QR bit
			Pattern: regexp.MustCompile(`^[\x00-\xff]{2}[\x80-\xff]`),
			Product: "DNS server",
		},
		{
			// SNMP GetResponse
			Pattern: regexp.MustCompile(`^\x30[\x00-\xff]*\xa2`),
			Product: "SNMP agent",
		},
		{
			// NTP server response
			Func: func(resp []byte) *MatchResult {
				if len(resp) >= 48 && resp[0]&0x07 == 4 {
					version := (resp[0] >> 3) & 0x07
					return &MatchResult{Product: "NTP server", Version: fmt.Sprintf("v%d", version)}
				}
				return nil
			},
		},
	},
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

// Builds the DHCP discover request
func dhcpProbe() []byte {
	p := make([]byte, 240)
	p[0] = 0x01 // BOOTREQUEST
	p[1] = 0x01 // Ethernet
	p[2] = 0x06 // MAC len
	p[4] = 0x39 // XID
	p[5] = 0x03
	p[6] = 0xf3
	p[7] = 0x26
	p[10] = 0x80 // Broadcast flag
	// Client MAC
	copy(p[28:], []byte("\x00\x0c\x29\x12\x34\x56"))
	// Magic cookie
	p[236] = 0x63
	p[237] = 0x82
	p[238] = 0x53
	p[239] = 0x63
	// Option 53: DHCP Discover, Option 255: End
	p = append(p, 53, 1, 1, 255)
	return p
}

// Returns the probes to send to a port
func UDPProbesFor(port string) []UDPProbe {
	p, err := strconv.Atoi(port)
	if err != nil {
		return []UDPProbe{genericUDPProbe}
	}

	var probes []UDPProbe
	for _, probe := range UDPProbes {
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
		if rule.Recog != "" {
			var recogInput string
			if len(idx) >= 4 && idx[2] >= 0 {
				recogInput = s[idx[2]:idx[3]]
			} else if len(idx) >= 2 && idx[0] >= 0 {
				recogInput = s[idx[0]:idx[1]]
			}
			if recogInput != "" {
				out = append(out, recogMatches(rule.Recog, recogInput)...)
			}
		}

		// Expands $1 etc. in the rule's fields
		expand := func(t string) string {
			return string(rule.Pattern.ExpandString(nil, t, s, idx))
		}
		fallback := MatchResult{
			Vendor:  expand(rule.Vendor),
			Product: expand(rule.Product),
			Version: expand(rule.Version),
		}
		if fallback.Vendor != "" || fallback.Product != "" || fallback.Version != "" {
			out = append(out, fallback)
		}
		return out
	}

	return nil
}