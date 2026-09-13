package fingerprinting

import (
	"embed"
	"fmt"

	"github.com/RumbleDiscovery/recog-go"
)

// Stores the recog files that are needed
var recogFiles embed.FS

// LoadEmbedded loads a specific embedded fingerprint file by name (e.g. "http_servers.xml").
// name is validated against the embedded FS's own namespace, so path traversal
// outside the embedded tree isn't possible via this function.
func LoadEmbedded(name string) (recog.FingerprintDB, error) {
	data, err := recogFiles.ReadFile("db/" + name)
	if err != nil {
		return recog.FingerprintDB{}, fmt.Errorf("read embedded fingerprint %q: %w", name, err)
	}
	return recog.LoadFingerprintDB(name, data)
}

// LoadAllEmbedded loads every .xml file under data/ into one merged DB.
func LoadAllPrints() (recog.FingerprintDB, error) {
	// Stores all of the directories entries
	entries, err := recogFiles.ReadDir("db")
	if err != nil {
		return recog.FingerprintDB{}, err
	}

	// Stores the merged files
	var merged recog.FingerprintDB
	
	// Loops over each entry
	for _, entry := range entries {
		// Checks if it is a directory
		if entry.IsDir() {
			continue
		}

		// Loads the embeded
		db, err := LoadEmbedded(entry.Name())
		if err != nil {
			return recog.FingerprintDB{}, err
		}

		// Merges the fingerprints
		merged.Fingerprints = append(merged.Fingerprints, db.Fingerprints...)
	}

	// Returns the merged
	return merged, nil
}