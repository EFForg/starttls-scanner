package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/sydneyli/starttls-scanner/db"
)

// ServePublicEndpoints serves all public HTTP endpoints.
func ServePublicEndpoints(api *API, cfg *db.Config) {
	http.HandleFunc("/api/scan", api.Scan)
	http.HandleFunc("/api/queue", api.Queue)
	http.HandleFunc("/api/validate", api.Validate)
	portString := fmt.Sprintf(":%s", cfg.Port)
	log.Fatal(http.ListenAndServe(portString, nil))
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
