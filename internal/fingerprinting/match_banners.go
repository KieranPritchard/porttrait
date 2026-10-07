package fingerprinting

import (
	"errors"
	"regexp"
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
	for _, target := range SelectTargets(banner, dbFiles) {
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
