package checker

import (
	"encoding/csv"
	"io"
	"log"
	"time"
)

// DomainTotals compiled aggregated stats across domains.
// Implements ResultHandler.
type DomainTotals struct {
	Time          time.Time
	Source        string
	Attempted     int
	Connected     int // Connected to at least one mx
	MTASTSTesting []string
	MTASTSEnforce []string
}

// HandleDomain adds the result of a single domain scan to aggregated stats.
func (t *DomainTotals) HandleDomain(r DomainResult) {
	t.Attempted++
	// Show progress.
	if t.Attempted%1000 == 0 {
		log.Printf("%+v\n", t)
	}

	// If DomainStatus is > 4, we couldn't connect to a mailbox.
	if r.Status > 4 {
		return
	}
	t.Connected++
	if r.MTASTSResult != nil {
		switch r.MTASTSResult.Mode {
		case "enforce":
			t.MTASTSEnforce = append(t.MTASTSEnforce, r.Domain)
		case "testing":
			t.MTASTSTesting = append(t.MTASTSTesting, r.Domain)
		}
	}
}

// ResultHandler processes domain results.
// It could print them, aggregate them, write the to the db, etc.
type ResultHandler interface {
	HandleDomain(DomainResult)
}

const poolSize = 16

// CheckCSV runs the checker on a csv of domains, processing the results according
// to resultHandler.
func (c *Checker) CheckCSV(domains *csv.Reader, resultHandler ResultHandler, domainColumn int) {
	work := make(chan string)
	results := make(chan DomainResult)

	go func() {
		for {
			data, err := domains.Read()
			if err != nil {
				if err != io.EOF {
					log.Fatal(err)
				}
				break
			}
			if len(data) > 0 {
				work <- data[domainColumn]
			}
		}
		close(work)
	}()

	done := make(chan struct{})
	for i := 0; i < poolSize; i++ {
		go func() {
			for domain := range work {
				results <- c.CheckDomain(domain, nil)
			}
			done <- struct{}{}
		}()
	}

	go func() {
		// Close the results channel when all the worker goroutines have finished.
		for i := 0; i < poolSize; i++ {
			<-done
		}
		close(results)
	}()

	for r := range results {
		resultHandler.HandleDomain(r)
	}
}
