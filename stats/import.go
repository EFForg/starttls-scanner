package stats

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	raven "github.com/getsentry/raven-go"
)

// Store wraps storage for MTA-STS adoption statistics.
type Store interface {
	PutAggregatedScan(checker.AggregatedScan) error
}

// Import imports JSON list of aggregated scans from a remote server to the
// datastore.
func Import(store Store) {
	statsURL := os.Getenv("REMOTE_STATS_URL")
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

// ImportRegularly runs Import to import aggregated stats from a remote server at regular intervals.
func ImportRegularly(store Store, interval time.Duration) {
	for {
		<-time.After(interval)
		Import(store)
	}
}
