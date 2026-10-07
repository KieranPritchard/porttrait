package fingerprinting

import (
	"errors"
	"html"
	"regexp"
	"sort"
	"strings"
)

// Type to store the banner match
type MatchResult struct {
	Vendor  string
	Product string
	Version string
}

// Stores a database file and the input to run against it
type matchTarget struct {
	dbFile string
	input  string
}

var htmlTitlePattern = regexp.MustCompile(`(?is)<title\b[^>]*>(.*?)</title\s*>`)

// Adds non-empty inputs once so multiline banners cannot produce duplicate targets.
func addMatchInput(inputs map[string][]string, dbFile, input string) {
	input = strings.TrimSpace(input)
	if input == "" {
		return
	}

	for _, existing := range inputs[dbFile] {
		if existing == input {
			return
		}
	}
	inputs[dbFile] = append(inputs[dbFile], input)
}

func httpBody(banner string) string {
	for _, separator := range []string{"\r\n\r\n", "\n\n"} {
		if i := strings.Index(banner, separator); i >= 0 {
			return banner[i+len(separator):]
		}
	}
	return ""
}

func httpHeaderValues(banner, headerName string) []string {
	var values []string
	for _, line := range strings.Split(banner, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), headerName) {
			values = append(values, strings.TrimSpace(value))
		}
	}
	return values
}

func httpStatusText(firstLine string) string {
	fields := strings.Fields(firstLine)
	if len(fields) < 3 {
		return ""
	}
	return strings.Join(fields[1:], " ")
}

// Works out which embedded databases and banner fragments apply to the response.
func selectTargets(banner string, dbFiles []string) []matchTarget {
	banner = strings.TrimSpace(banner)
	if banner == "" {
		return nil
	}

	inputs := make(map[string][]string)
	firstLine := strings.TrimSpace(strings.SplitN(banner, "\n", 2)[0])

	switch {
	case strings.HasPrefix(strings.ToUpper(firstLine), "HTTP/"):
		addMatchInput(inputs, "http_servers.xml", extractServerHeader(banner))
		for _, value := range httpHeaderValues(banner, "WWW-Authenticate") {
			addMatchInput(inputs, "http_wwwauth.xml", value)
		}
		for _, value := range httpHeaderValues(banner, "Set-Cookie") {
			addMatchInput(inputs, "http_cookies.xml", value)
		}
		for _, value := range httpHeaderValues(banner, "X-Powered-By") {
			addMatchInput(inputs, "http_xpoweredby.xml", value)
		}
		addMatchInput(inputs, "html_title.xml", httpStatusText(firstLine))
		if title := htmlTitlePattern.FindStringSubmatch(httpBody(banner)); len(title) == 2 {
			addMatchInput(inputs, "html_title.xml", html.UnescapeString(title[1]))
		}

	case strings.HasPrefix(firstLine, "SSH-"):
		parts := strings.SplitN(firstLine, "-", 3)
		if len(parts) == 3 {
			addMatchInput(inputs, "ssh_banners.xml", parts[2])
		}

	case strings.HasPrefix(firstLine, "220"):
		// FTP and SMTP both greet with 220; the Recog patterns expect the text after it.
		for _, line := range strings.Split(banner, "\n") {
			line = strings.TrimSpace(line)
			if len(line) >= 4 && line[:3] == "220" && (line[3] == ' ' || line[3] == '-') {
				addMatchInput(inputs, "ftp_banners.xml", line)
				addMatchInput(inputs, "smtp_banners.xml", line)
				addMatchInput(inputs, "ftp_banners.xml", line[4:])
				addMatchInput(inputs, "smtp_banners.xml", line[4:])
			}
		}

	case strings.HasPrefix(firstLine, "+OK") || strings.HasPrefix(firstLine, "-ERR"):
		for _, line := range strings.Split(banner, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "+OK") || strings.HasPrefix(line, "-ERR") {
				addMatchInput(inputs, "pop_banners.xml", strings.TrimSpace(line[3:]))
			}
		}

	case strings.HasPrefix(firstLine, "* OK") || strings.HasPrefix(firstLine, "* PREAUTH"):
		for _, line := range strings.Split(banner, "\n") {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "* OK"):
				addMatchInput(inputs, "imap_banners.xml", strings.TrimSpace(line[len("* OK"):]))
			case strings.HasPrefix(line, "* PREAUTH"):
				addMatchInput(inputs, "imap_banners.xml", strings.TrimSpace(line[len("* PREAUTH"):]))
			}
		}

	case strings.HasPrefix(firstLine, "200") || strings.HasPrefix(firstLine, "201"):
		// NNTP servers greet with 200 (posting allowed) or 201 (no posting).
		// Try both NNTP-specific and the generic SMTP/FTP databases because 200/201
		// can occasionally appear in other protocols.
		for _, line := range strings.Split(banner, "\n") {
			line = strings.TrimSpace(line)
			code := ""
			if len(line) >= 4 && (line[:3] == "200" || line[:3] == "201") && (line[3] == ' ' || line[3] == '-') {
				code = line[:3]
			}
			if code != "" {
				addMatchInput(inputs, "nntp_banners.xml", line)
				addMatchInput(inputs, "nntp_banners.xml", line[4:])
			}
		}

	case strings.HasPrefix(strings.ToUpper(firstLine), "SIP/"):
		// SIP responses — extract the Server header for sip_banners.xml
		for _, value := range httpHeaderValues(banner, "Server") {
			addMatchInput(inputs, "sip_banners.xml", value)
		}
		for _, value := range httpHeaderValues(banner, "User-Agent") {
			addMatchInput(inputs, "sip_banners.xml", value)
		}

	case strings.HasPrefix(strings.ToUpper(firstLine), "@PJL"):
		// HP PJL (Printer Job Language) responses
		addMatchInput(inputs, "hp_pjl_id.xml", banner)
		addMatchInput(inputs, "hp_pjl_id.xml", firstLine)

	case isMySQLGreeting(banner):
		// MySQL sends a greeting packet whose version string starts at byte 5.
		// The version is null-terminated ASCII — extract and match it.
		if ver := extractMySQLVersion(banner); ver != "" {
			addMatchInput(inputs, "mysql_banners.xml", ver)
		}

	default:
		addMatchInput(inputs, "telnet_banners.xml", banner)
	}

	// Use sorted database names so match ordering remains stable if files are added.
	names := append([]string(nil), dbFiles...)
	sort.Strings(names)

	var targets []matchTarget
	for _, name := range names {
		for _, input := range inputs[name] {
			targets = append(targets, matchTarget{dbFile: name, input: input})
		}
	}
	return targets
}

// isMySQLGreeting returns true if the banner looks like a MySQL server greeting.
// A MySQL greeting starts with a packet-length header, protocol version byte (0x0a
// for the current protocol), then a null-terminated version string.
func isMySQLGreeting(banner string) bool {
	// Minimum: 1 byte protocol + at least 3 chars of version + null terminator
	if len(banner) < 5 {
		return false
	}
	// Protocol version 10 (0x0a) is the most common; some very old servers use 9.
	// The banner grabber cleans non-printable bytes, so the version string may start
	// directly if the leading bytes were stripped. Heuristic: if it looks like a
	// dotted version (e.g. "5.7.42-log") it's likely MySQL.
	return mysqlVersionPattern.MatchString(banner)
}

// extractMySQLVersion pulls the version string out of a (cleaned) MySQL greeting.
func extractMySQLVersion(banner string) string {
	m := mysqlVersionPattern.FindString(banner)
	return m
}

var mysqlVersionPattern = regexp.MustCompile(`(?m)^[0-9]+\.[0-9]+[.\-][0-9a-zA-Z._\-]+`)

func MatchBanners(banner string) ([]MatchResult, error) {
	if strings.TrimSpace(banner) == "" {
		return nil, errors.New("banner is empty")
	}

	// Brings in the embedded databases (loaded once).
	dbs, err := LoadAllPrints()
	if err != nil {
		return nil, err
	}

	dbFiles := make([]string, 0, len(dbs))
	for name := range dbs {
		dbFiles = append(dbFiles, name)
	}

	matchList := make([]MatchResult, 0)
	seen := make(map[MatchResult]struct{})
	for _, target := range selectTargets(banner, dbFiles) {
		db, ok := dbs[target.dbFile]
		if !ok {
			continue
		}

		for _, match := range db.MatchAll(target.input) {
			currentMatch := MatchResult{
				Vendor:  match.Values["service.vendor"],
				Product: match.Values["service.product"],
				Version: match.Values["service.version"],
			}
			if currentMatch.Vendor == "" && currentMatch.Product == "" && currentMatch.Version == "" {
				continue
			}
			if _, exists := seen[currentMatch]; exists {
				continue
			}
			seen[currentMatch] = struct{}{}
			matchList = append(matchList, currentMatch)
		}
	}

	return matchList, nil
}
