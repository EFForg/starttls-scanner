package main

import (
	"encoding/csv"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/db"
	raven "github.com/getsentry/raven-go"
	"github.com/joho/godotenv"
)

func main() {
	if len(os.Args) <= 1 {
		log.Println("Please specify a task")
		os.Exit(1)
	}

	godotenv.Load("../.env")
	raven.SetDSN(os.Getenv("SENTRY_URL"))
	cfg, err := db.LoadEnvironmentVariables()
	if err != nil {
		log.Fatal(err)
	}
	db, err := db.InitSQLDatabase(cfg)
	if err != nil {
		log.Fatal(err)
	}

	switch os.Args[1] {
	case "update-stats":
		updateStats("http://downloads.majestic.com/majestic_million.csv", db)
	}
}

func updateStats(url string, db db.Database) {
	resp, err := http.Get(url)
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
