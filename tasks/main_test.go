package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/EFForg/starttls-backend/db"
	"github.com/joho/godotenv"
)

func TestMain(m *testing.M) {
	godotenv.Overload("../.env.test")
}

func TestUpdateStats(t *testing.T) {
	cfg, err := db.LoadEnvironmentVariables()
	if err != nil {
		log.Fatal(err)
	}
	sqldb, err := db.InitSQLDatabase(cfg)
	if err != nil {
		log.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `1, foo, example1.com
1, bar, example2.com
3, baz, example3.com`)
	}))
	defer ts.Close()

	updateStats(ts.URL, sqldb)
	// @TODO test that we can read out stats correctly, pending code to read
	// stats.
}
