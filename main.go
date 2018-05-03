package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/EFForg/starttls-scanner/db"
	"github.com/gorilla/handlers"
)

func validPort(port string) (string, error) {
	if _, err := strconv.Atoi(port); err != nil {
		return "", fmt.Errorf("Given portstring %s is invalid.", port)
	}
	return fmt.Sprintf(":%s", port), nil
}

// ServePublicEndpoints serves all public HTTP endpoints.
func ServePublicEndpoints(api *API, cfg *db.Config) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/scan", api.Scan)
	mux.HandleFunc("/api/queue", api.Queue)
	mux.HandleFunc("/api/validate", api.Validate)
	portString, err := validPort(cfg.Port)
	if err != nil {
		log.Fatal(err)
	}
	requestLogger := handlers.LoggingHandler(os.Stdout, mux)
	log.Fatal(http.ListenAndServe(portString, requestLogger))
}

func main() {
	cfg, err := db.LoadEnvironmentVariables()
	if err != nil {
		log.Fatal(err)
	}
	db, err := db.InitSqlDatabase(cfg)
	if err != nil {
		log.Fatal(err)
	}
	api := API{
		Database: db,
	}
	ServePublicEndpoints(&api, &cfg)
}
