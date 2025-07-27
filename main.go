package main

import (
	"log"
	"net/http"

	"github.com/felipemarinho97/magnet-metadata-api/config"
	"github.com/felipemarinho97/magnet-metadata-api/torrent"
)

func main() {
	config := config.LoadConfig()

	log.Printf("Starting Torrent Metadata API Service")
	log.Printf("Config: Port=%s, CacheDir=%s, EnableDownloads=%v, SeedingEnabled=%v",
		config.Port, config.CacheDir, config.EnableDownloads, config.SeedingEnabled)

	service, err := torrent.NewTorrentService(config)
	if err != nil {
		log.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	router := service.SetupRoutes()

	log.Printf("Server listening on port %s", config.Port)
	if err := http.ListenAndServe(":"+config.Port, router); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
