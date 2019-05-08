package stats

import (
	"encoding/json"
	"net/http"

	"github.com/EFForg/starttls-backend/checker"
	raven "github.com/getsentry/raven-go"
)

var statsURL = "https://stats.starttls-everywhere.org/mta-sts-adoption.csv"

// Store wraps storage for MTA-STS adoption statistics.
type Store interface {
	PutAggregatedScan(checker.AggregatedScan) error
}

// Import imports JSON list of aggregated scans from a remote server to the
// datastore.
func Import(store Store) {
	resp, err := http.Get(statsURL)
	if err != nil {
		raven.CaptureError(err, nil)
		return
	}
	defer resp.Body.Close()

	var agScans []checker.AggregatedScan
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&agScans)
	if err != nil {
		raven.CaptureError(err, nil)
		return
	}
	for _, a := range agScans {
		err := store.PutAggregatedScan(a)
		if err != nil {
			raven.CaptureError(err, nil)
		}
	}
}
