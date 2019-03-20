package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// func TestMain(m *testing.M) {
// 	godotenv.Overload("../.env.test")
// 	code := m.Run()
// 	os.Exit(code)
// }

func TestUpdateStats(t *testing.T) {
	// cfg, err := db.LoadEnvironmentVariables()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// database, err := db.InitSQLDatabase(cfg)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `example1.com
example2.com
example3.com`)
	}))
	defer ts.Close()

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"starttls-checker", "-url", ts.URL, "-aggregate=true"}

	main()
	// @TODO make this faster!
	// @TODO test that we can read out stats correctly, pending code to read stats.
}
