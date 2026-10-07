package fingerprinting

import (
	"errors"
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

// Works out which databases and inputs apply to the banner
func selectTargets(banner string) ([]matchTarget, error) {
	if strings.TrimSpace(banner) == "" {
		return nil, errors.New("banner is empty")
	}

	// Trims whitespace and takes the first line of the banner
	banner = strings.TrimSpace(banner)
	firstLine := strings.TrimSpace(strings.SplitN(banner, "\n", 2)[0])

	switch {
	case strings.HasPrefix(banner, "HTTP/"):
		return []matchTarget{{"http_servers.xml", extractServerHeader(banner)}}, nil
	case strings.HasPrefix(banner, "SSH-"):
		return []matchTarget{{"ssh_banners.xml", firstLine}}, nil
	case strings.HasPrefix(banner, "220"):
		// FTP and SMTP both greet with 220, so tries both
		return []matchTarget{
			{"ftp_banners.xml", firstLine},
			{"smtp_banners.xml", firstLine},
		}, nil
	}

	return nil, errors.New("no matching database for banner")
}

func MatchBanners(banner string) ([]MatchResult, error) {
	if strings.TrimSpace(banner) == "" {
		return nil, errors.New("banner is empty")
	}

	// Creates the matches list
	matchList := make([]MatchResult, 0)

	// Nothing to match against
	if strings.TrimSpace(banner) == "" {
		return matchList, nil
	}

	// Brings in the embedded databases (loaded once)
	dbs, err := LoadAllPrints()
	if err != nil {
		return nil, err
	}

	// Loops over each database that applies to this banner
	for _, target := range selectTargets(banner) {
		// Skips if there is nothing to match, e.g. no Server header
		if target.input == "" {
			continue
		}

		// Skips if the database wasn't embedded
		db, ok := dbs[target.dbFile]
		if !ok {
			continue
		}

		// Gets all of the matches
		for _, match := range db.MatchAll(target.input) {
			// Builds the current match type
			currentMatch := MatchResult{
				Vendor:  match.Values["service.vendor"],
				Product: match.Values["service.product"],
				Version: match.Values["service.version"],
			}

			// Skips matches that identified nothing useful
			if currentMatch.Vendor == "" && currentMatch.Product == "" && currentMatch.Version == "" {
				continue
			}

			// Adds to the match list
			matchList = append(matchList, currentMatch)
		}
	}

	return matchList, nil
}