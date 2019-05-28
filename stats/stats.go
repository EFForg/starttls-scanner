package stats

import (
	"bufio"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	raven "github.com/getsentry/raven-go"
)

// Store wraps storage for MTA-STS adoption statistics.
type Store interface {
	PutAggregatedScan(checker.AggregatedScan) error
	PutLocalStats(time.Time) (checker.AggregatedScan, error)
	GetStats(string) (Series, error)
}

// Identifier in the DB for aggregated scans we imported from our regular scans
// of the web's top domains
const topDomainsSource = "TOP_DOMAINS"

// Import imports aggregated scans from a remote server to the datastore.
// Expected format is JSONL (newline-separated JSON objects).
func Import(store Store) error {
	statsURL := os.Getenv("REMOTE_STATS_URL")
	resp, err := http.Get(statsURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	s := bufio.NewScanner(resp.Body)
	for s.Scan() {
		var a checker.AggregatedScan
		err := json.Unmarshal(s.Bytes(), &a)
		if err != nil {
			return err
		}
		a.Source = topDomainsSource
		err = store.PutAggregatedScan(a)
		if err != nil {
			return err
		}
	}
	if err := s.Err(); err != nil {
		return err
	}
	return nil
}

// Update imports aggregated scans and update our cache table of local scans.
// Log any errors.
func Update(store Store) {
	err := Import(store)
	if err != nil {
		log.Println(err)
		raven.CaptureError(err, nil)
	}
	// Cache stats for the previous day at midnight. This ensures that we capture
	// full days and maintain regularly intervals.
	_, err = store.PutLocalStats(time.Now().UTC().Truncate(24 * time.Hour))
	if err != nil {
		log.Println(err)
		raven.CaptureError(err, nil)
	}
}

// UpdateRegularly runs Import to import aggregated stats from a remote server at regular intervals.
func UpdateRegularly(store Store, interval time.Duration) {
	for {
		Update(store)
		<-time.After(interval)
	}
}

// Series represents some statistic as it changes over time.
// This will likely be updated when we know what format our frontend charting
// library prefers.
type Series []checker.AggregatedScan

// MarshalJSON marshals a Series to the format expected by chart.js.
func (s Series) MarshalJSON() ([]byte, error) {
	type xyPt struct {
		X time.Time `json:"x"`
		Y float64   `json:"y"`
	}
	xySeries := make([]xyPt, 0)
	for _, a := range s {
		var y float64
		if a.Source != topDomainsSource {
			y = a.PercentMTASTS()
		} else {
			// Top million scans have too few MTA-STS domains to use a percent,
			// display a raw total instead.
			y = float64(a.TotalMTASTS())
		}
		xySeries = append(xySeries, xyPt{X: a.Time, Y: y})
	}
	return json.Marshal(xySeries)
}

// Get retrieves MTA-STS adoption statistics for user-initiated scans and scans
// of the top million domains over time.
func Get(store Store) (map[string]Series, error) {
	result := make(map[string]Series)
	series, err := store.GetStats(topDomainsSource)
	if err != nil {
		return result, err
	}
	result["top_million"] = series
	series, err = store.GetStats("local")
	if err != nil {
		return result, err
	}
	result["local"] = series
	return result, err
}
