package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPanicRecovery(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Expected server to handle panic")
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/panic", panickingHandler)
	server := httptest.NewServer(registerHandlers(api, mux))
	defer server.Close()

	resp, err := http.Get(fmt.Sprintf("%s/panic", server.URL))

	if err != nil {
		t.Errorf("Request to panic endpoint failed: %s\n", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected server to respond with 500, got %d", resp.StatusCode)
	}
}

func panickingHandler(w http.ResponseWriter, r *http.Request) {
	panic(fmt.Errorf("oh no"))
}

func TestThrottleByIP(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(registerHandlers(api, mux))
	defer server.Close()

	for i := 0; i < 10; i++ {
		http.Get(fmt.Sprintf("%s/", server.URL))
	}
	resp, err := http.Get(fmt.Sprintf("%s/", server.URL))

	if err != nil {
		t.Errorf("Rate limit request failed: %s\n", err)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected server to respond with 429, got %d", resp.StatusCode)
	}
}
