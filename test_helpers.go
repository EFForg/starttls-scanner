package main

import (
	"net/http"
	"net/http/httptest"
)

func Setup() *httptest.Server {
	mux := http.NewServeMux()
	return httptest.NewServer(registerHandlers(api, mux))
}

func Teardown(server *httptest.Server) {
	server.Close()
}
