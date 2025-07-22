package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port            string
	RedisURL        string
	CacheDir        string
	EnableDownloads bool
	DownloadBaseURL string
	DHTPeers        []string
	ClientPort      int
	SeedingEnabled  bool
}

func LoadConfig() *Config {
	config := &Config{
		Port:            getEnv("PORT", "8080"),
		RedisURL:        getEnv("REDIS_URL", "redis://localhost:6379"),
		CacheDir:        getEnv("CACHE_DIR", "./cache"),
		EnableDownloads: getEnv("ENABLE_DOWNLOADS", "false") == "true",
		DownloadBaseURL: getEnv("DOWNLOAD_BASE_URL", "http://localhost:8080"),
		ClientPort:      getEnvInt("CLIENT_PORT", 42069),
		SeedingEnabled:  getEnv("SEEDING_ENABLED", "true") == "true",
	}

	// Default DHT bootstrap nodes
	config.DHTPeers = []string{
		"router.bittorrent.com:6881",
		"dht.transmissionbt.com:6881",
		"router.utorrent.com:6881",
		"dht.aelitis.com:6881",
	}

	return config
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}
