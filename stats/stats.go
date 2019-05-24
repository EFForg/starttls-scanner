package stats

import (
	"bufio"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	raven "github.com/getsentry/raven-go"
)

// Store wraps storage for MTA-STS adoption statistics.
type Store interface {
	PutAggregatedScan(checker.AggregatedScan) error
	GetMTASTSStats(string) (Series, error)
	GetMTASTSLocalStats() (Series, error)
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

// ImportRegularly runs Import to import aggregated stats from a remote server at regular intervals.
func ImportRegularly(store Store, interval time.Duration) {
	for {
		err := Import(store)
		if err != nil {
			log.Println(err)
			raven.CaptureError(err, nil)
		}
		<-time.After(interval)
	}
}

// Series represents some statistic as it changes over time.
// This will likely be updated when we know what format our frontend charting
// library prefers.
type Series map[time.Time]checker.AggregatedScan

// MarshalJSON marshals a Series to the format expected by chart.js.
func (s Series) MarshalJSON() ([]byte, error) {
	type xyPt struct {
		X time.Time `json:"x"`
		Y float64   `json:"y"`
	}
	xySeries := make([]xyPt, 0)
	for t, a := range s {
		var y float64
		if a.Source != topDomainsSource {
			y = a.PercentMTASTS()
		} else {
			// Top million scans have too few MTA-STS domains to use a percent,
			// display a raw total instead.
			y = float64(a.TotalMTASTS())
		}
		xySeries = append(xySeries, xyPt{X: t, Y: y})
	}
	sort.Slice(xySeries, func(i, j int) bool {
		return xySeries[i].X.After(xySeries[j].X)
	})
	return json.Marshal(xySeries)
}

// Get retrieves MTA-STS adoption statistics for user-initiated scans and scans
// of the top million domains over time.
func Get(store Store) (map[string]Series, error) {
	result := make(map[string]Series)
	series, err := store.GetMTASTSStats(topDomainsSource)
	if err != nil {
		return result, err
	}
	result["top_million"] = series
	series, err = store.GetMTASTSStats("local")
	if err != nil {
		return result, err
	}
	result["local"] = series
	return result, err
}
