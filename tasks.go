package main

import (
	"encoding/csv"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/db"
)

func runTask(name string, db db.Database) {
	switch name {
	case "update-stats":
		updateStats(db)
	}
}

func updateStats(db db.Database) {
	resp, err := http.Get("http://downloads.majestic.com/majestic_million.csv")
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	domains := csv.NewReader(resp.Body)
	totals := checker.DomainTotals{
		Time:   time.Now(),
		Source: "majestic-million",
	}
	c := checker.Checker{
		Cache: checker.MakeSimpleCache(10 * time.Minute),
	}
	c.CheckCSV(domains, &totals, 2)
	db.PutDomainTotals(totals)
	log.Printf("Scans completed, got %+v\n", totals)
}
