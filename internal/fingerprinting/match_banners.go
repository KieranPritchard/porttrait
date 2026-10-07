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

// Pattern to extract the HTML title from a banner
var htmlTitlePattern = regexp.MustCompile(`(?is)<title\b[^>]*>(.*?)</title\s*>`)

// Adds non-empty inputs once so multiline banners cannot produce duplicate targets.
func addMatchInput(inputs map[string][]string, dbFile, input string) {
	// Trim whitespace and skip empty inputs
	input = strings.TrimSpace(input)
	if input == "" {
		return
	}

	// Look for duplicates and only add if not already present
	for _, existing := range inputs[dbFile] {
		if existing == input {
			return
		}
	}
	// Add the input to the list for this database file
	inputs[dbFile] = append(inputs[dbFile], input)
}

// Extracts the Server header from an HTTP banner, if present.
func httpBody(banner string) string {
	// Look for the first occurrence of a double CRLF or double LF, which indicates the end of headers
	for _, separator := range []string{"\r\n\r\n", "\n\n"} {
		// Find the index of the separator in the banner
		if i := strings.Index(banner, separator); i >= 0 {
			// Return the substring after the separator, which is the body of the HTTP response
			return banner[i+len(separator):]
		}
	}
	return ""
}

// Extracts the Server header from an HTTP banner, if present.
func httpHeaderValues(banner, headerName string) []string {
	// Store the values of the specified header in a slice
	var values []string

	// Split the banner into lines and iterate over them
	for _, line := range strings.Split(banner, "\n") {
		// Trim whitespace from the line and check if it's empty; if so, stop processing headers
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		// Split the line into a name and value using the first colon as a separator
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), headerName) {
			values = append(values, strings.TrimSpace(value))
		}
	}
	// Return the collected header values; if none were found, this will be an empty slice
	return values
}

// Extracts the status text from the first line of an HTTP response, which is typically in the format "HTTP/1.1 200 OK".
func httpStatusText(firstLine string) string {
	// Split the first line into fields (e.g., "HTTP/1.1", "200", "OK")
	fields := strings.Fields(firstLine)
	if len(fields) < 3 {
		return ""
	}
	// Join the fields after the first two (status code) to get the status text (e.g., "OK")
	return strings.Join(fields[1:], " ")
}

// Works out which embedded databases and banner fragments apply to the response.
func selectTargets(banner string, dbFiles []string) []matchTarget {
	// Trim whitespace from the banner and return nil if it's empty
	banner = strings.TrimSpace(banner)
	if banner == "" {
		return nil
	}

	// Map to hold database files and their corresponding banner fragments
	inputs := make(map[string][]string)
	firstLine := strings.TrimSpace(strings.SplitN(banner, "\n", 2)[0])

	// Determine the type of banner based on its first line and extract relevant inputs for matching
	switch {
	// HTTP responses — extract the Server header for http_servers.xml
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
	// SSH banners — extract the version string for ssh_banners.xml
	case strings.HasPrefix(firstLine, "SSH-"):
		parts := strings.SplitN(firstLine, "-", 3)
		if len(parts) == 3 {
			addMatchInput(inputs, "ssh_banners.xml", parts[2])
		}
	// FTP and SMTP both greet with 220; the Recog patterns expect the text after it.
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
	// POP3 and IMAP both greet with +OK or * OK; the Recog patterns expect the text after it.
	case strings.HasPrefix(firstLine, "+OK") || strings.HasPrefix(firstLine, "-ERR"):
		for _, line := range strings.Split(banner, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "+OK") || strings.HasPrefix(line, "-ERR") {
				addMatchInput(inputs, "pop_banners.xml", strings.TrimSpace(line[3:]))
			}
		}
	// IMAP can also greet with * OK or * PREAUTH, which is handled in the next case.
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
	// NNTP servers greet with 200 (posting allowed) or 201 (no posting).
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
	// SIP responses — extract the Server header for sip_banners.xml
	case strings.HasPrefix(strings.ToUpper(firstLine), "SIP/"):
		// SIP responses — extract the Server header for sip_banners.xml
		for _, value := range httpHeaderValues(banner, "Server") {
			addMatchInput(inputs, "sip_banners.xml", value)
		}
		for _, value := range httpHeaderValues(banner, "User-Agent") {
			addMatchInput(inputs, "sip_banners.xml", value)
		}

	// PJL responses start with @PJL and contain the printer model in the INFO ID response.
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
