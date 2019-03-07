package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUpdateStats(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `1, foo, example1.com
1, bar, example2.com
3, baz, example3.com`)
	}))
	defer ts.Close()

	updateStats(ts.URL, api.Database)
	// @TODO test that we can read out stats correctly, pending code to read
	// stats.
}
