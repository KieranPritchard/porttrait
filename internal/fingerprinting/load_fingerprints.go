package fingerprinting

import (
	"embed"
	"fmt"
	"strings"
	"sync"

	"github.com/RumbleDiscovery/recog-go"
)

// Stores the recog files that are needed
//
//go:embed db/*
var recogFiles embed.FS

// Stores the loaded databases, keyed by file name
var (
	dbs     map[string]recog.FingerprintDB
	dbsErr  error
	dbsOnce sync.Once
)

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

// LoadAllPrints loads every .xml file under db/ once and keeps them separate
func LoadAllPrints() (map[string]recog.FingerprintDB, error) {
	dbsOnce.Do(func() {
		// Stores all of the directories entries
		entries, err := recogFiles.ReadDir("db")
		if err != nil {
			dbsErr = err
			return
		}

		dbs = make(map[string]recog.FingerprintDB)

		// Loops over each entry
		for _, entry := range entries {
			// Skips directories and non xml files
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".xml") {
				continue
			}

			// Loads the embedded file
			db, err := LoadEmbedded(entry.Name())
			if err != nil {
				dbsErr = err
				return
			}

			dbs[entry.Name()] = db
		}
	})

	return dbs, dbsErr
}

// Pulls the Server header value out of an HTTP response
func extractServerHeader(banner string) string {
	for _, line := range strings.Split(banner, "\n") {
		line = strings.TrimSpace(line)
		if len(line) > 7 && strings.EqualFold(line[:7], "server:") {
			return strings.TrimSpace(line[7:])
		}
	}
	return ""
}
