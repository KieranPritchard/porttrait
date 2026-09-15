package fingerprinting

// Type to store the banner match
type matchResult struct {
	vender  string
	service string
	version string
}

func MatchBanners(banner string) ([]matchResult, error) {
	// Creates the matches list
	matchList := make([]matchResult, 0)

	// Brings in the embedded database
	db, err := LoadAllPrints()
	if err != nil {
		return nil, err
	}

	// Gets all fo the matches
	for _, match := range db.MatchAll(banner) {

		// Stores the current match
		var currentMatch matchResult

		// Builds the current match type
		currentMatch.vender = match.Values["service.vendor"]
		currentMatch.service = match.Values["service.product"]
		currentMatch.version = match.Values["service.version"]

		// Adds to the match list
		matchList = append(matchList, currentMatch)
	}

	return matchList, nil
}
