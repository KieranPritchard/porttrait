package fingerprinting

import (
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