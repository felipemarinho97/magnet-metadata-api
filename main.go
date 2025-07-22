package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/anacrolix/torrent/storage"
	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
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

type TorrentService struct {
	config      *Config
	client      *torrent.Client
	redisClient *redis.Client
	ctx         context.Context
}

type TorrentMetadata struct {
	InfoHash    string     `json:"info_hash"`
	Name        string     `json:"name"`
	Size        int64      `json:"size"`
	Files       []FileInfo `json:"files"`
	CreatedBy   string     `json:"created_by,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	Comment     string     `json:"comment,omitempty"`
	Trackers    []string   `json:"trackers,omitempty"`
	DownloadURL *string    `json:"download_url,omitempty"`
}

type FileInfo struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Offset int64  `json:"offset"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type MagnetRequest struct {
	MagnetURI string `json:"magnet_uri"`
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

func NewTorrentService(config *Config) (*TorrentService, error) {
	ctx := context.Background()

	// Setup Redis client
	opt, err := redis.ParseURL(config.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid redis URL: %w", err)
	}
	redisClient := redis.NewClient(opt)

	// Test Redis connection
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Printf("Warning: Redis connection failed: %v. Using disk cache only.", err)
		redisClient = nil
	}

	// Create cache directory
	if err := os.MkdirAll(config.CacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Configure torrent client
	clientConfig := torrent.NewDefaultClientConfig()
	clientConfig.DataDir = config.CacheDir
	clientConfig.ListenPort = config.ClientPort
	clientConfig.DisableTrackers = false
	clientConfig.NoDHT = false
	clientConfig.DisableUTP = false
	clientConfig.Seed = config.SeedingEnabled

	// Use memory storage to avoid downloading actual files
	clientConfig.DefaultStorage = storage.NewMMap(config.CacheDir)

	client, err := torrent.NewClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create torrent client: %w", err)
	}

	service := &TorrentService{
		config:      config,
		client:      client,
		redisClient: redisClient,
		ctx:         ctx,
	}

	return service, nil
}

func (ts *TorrentService) Close() error {
	if ts.client != nil {
		ts.client.Close()
	}
	if ts.redisClient != nil {
		return ts.redisClient.Close()
	}
	return nil
}

func (ts *TorrentService) parseMagnetURI(magnetURI string) (metainfo.Hash, error) {
	u, err := url.Parse(magnetURI)
	if err != nil {
		return metainfo.Hash{}, fmt.Errorf("invalid magnet URI: %w", err)
	}

	if u.Scheme != "magnet" {
		return metainfo.Hash{}, fmt.Errorf("not a magnet URI")
	}

	params := u.Query()
	xt := params.Get("xt")
	if xt == "" {
		return metainfo.Hash{}, fmt.Errorf("missing xt parameter")
	}

	if !strings.HasPrefix(xt, "urn:btih:") {
		return metainfo.Hash{}, fmt.Errorf("unsupported xt format")
	}

	hashStr := strings.TrimPrefix(xt, "urn:btih:")

	var infoHash metainfo.Hash
	if len(hashStr) == 40 {
		// SHA1 hex format
		hashBytes, err := hex.DecodeString(hashStr)
		if err != nil {
			return metainfo.Hash{}, fmt.Errorf("invalid hex hash: %w", err)
		}
		copy(infoHash[:], hashBytes)
	} else {
		return metainfo.Hash{}, fmt.Errorf("unsupported hash format")
	}

	return infoHash, nil
}

func (ts *TorrentService) getCachedMetadata(infoHash string) (*TorrentMetadata, error) {
	// Try Redis cache first
	if ts.redisClient != nil {
		cached, err := ts.redisClient.Get(ts.ctx, "metadata:"+infoHash).Result()
		if err == nil {
			var metadata TorrentMetadata
			if err := json.Unmarshal([]byte(cached), &metadata); err == nil {
				return &metadata, nil
			}
		}
	}

	// Try disk cache
	cachePath := filepath.Join(ts.config.CacheDir, infoHash+".json")
	if data, err := os.ReadFile(cachePath); err == nil {
		var metadata TorrentMetadata
		if err := json.Unmarshal(data, &metadata); err == nil {
			return &metadata, nil
		}
	}

	return nil, nil
}

func (ts *TorrentService) cacheMetadata(metadata *TorrentMetadata) error {
	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	// Cache in Redis with 24h expiration
	if ts.redisClient != nil {
		ts.redisClient.Set(ts.ctx, "metadata:"+metadata.InfoHash, data, 24*time.Hour)
	}

	// Cache on disk
	cachePath := filepath.Join(ts.config.CacheDir, metadata.InfoHash+".json")
	return os.WriteFile(cachePath, data, 0644)
}

func (ts *TorrentService) getTorrentMetadata(magnetURI string) (*TorrentMetadata, error) {
	infoHash, err := ts.parseMagnetURI(magnetURI)
	if err != nil {
		return nil, err
	}

	infoHashStr := hex.EncodeToString(infoHash[:])

	// Check cache first
	if cached, err := ts.getCachedMetadata(infoHashStr); cached != nil && err == nil {
		log.Printf("Cache hit for info hash: %s", infoHashStr)
		return cached, nil
	}

	log.Printf("Cache miss, fetching metadata for info hash: %s", infoHashStr)

	// Add torrent to client
	t, err := ts.client.AddMagnet(magnetURI)
	if err != nil {
		return nil, fmt.Errorf("failed to add magnet: %w", err)
	}

	// Wait for info with timeout
	select {
	case <-t.GotInfo():
		log.Printf("Got info for torrent: %s", t.Name())
	case <-time.After(30 * time.Second):
		t.Drop()
		return nil, fmt.Errorf("timeout waiting for torrent info")
	}

	defer func() {
		if !ts.config.SeedingEnabled {
			t.Drop()
		}
	}()

	// Extract metadata
	info := t.Info()
	if info == nil {
		return nil, fmt.Errorf("failed to get torrent info")
	}

	files := make([]FileInfo, len(info.Files))
	var offset int64
	for i, file := range info.Files {
		files[i] = FileInfo{
			Path:   strings.Join(file.Path, "/"),
			Size:   file.Length,
			Offset: offset,
		}
		offset += file.Length
	}

	metadata := &TorrentMetadata{
		InfoHash: infoHashStr,
		Name:     info.Name,
		Size:     info.TotalLength(),
		Files:    files,
		Comment:  t.Metainfo().Comment,
	}

	if t.Metainfo().CreatedBy != "" {
		metadata.CreatedBy = t.Metainfo().CreatedBy
	}

	if !(t.Metainfo().CreationDate == 0) {
		timeParsed := time.Unix(t.Metainfo().CreationDate, 0)
		metadata.CreatedAt = &timeParsed
	}

	// Extract trackers
	for _, tier := range t.Metainfo().AnnounceList {
		for _, tracker := range tier {
			metadata.Trackers = append(metadata.Trackers, tracker)
		}
	}

	// Add download URL if enabled
	if ts.config.EnableDownloads {
		downloadURL := fmt.Sprintf("%s/download/%s",
			strings.TrimSuffix(ts.config.DownloadBaseURL, "/"),
			infoHashStr)
		metadata.DownloadURL = &downloadURL
	}

	// Cache the metadata
	if err := ts.cacheMetadata(metadata); err != nil {
		log.Printf("Failed to cache metadata: %v", err)
	}

	return metadata, nil
}

func (ts *TorrentService) handleGetMetadata(w http.ResponseWriter, r *http.Request) {
	var req MagnetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ts.writeError(w, http.StatusBadRequest, "Invalid JSON", err.Error())
		return
	}

	if req.MagnetURI == "" {
		ts.writeError(w, http.StatusBadRequest, "Missing magnet URI", "magnet_uri field is required")
		return
	}

	metadata, err := ts.getTorrentMetadata(req.MagnetURI)
	if err != nil {
		ts.writeError(w, http.StatusInternalServerError, "Failed to get torrent metadata", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}

func (ts *TorrentService) handleDownload(w http.ResponseWriter, r *http.Request) {
	if !ts.config.EnableDownloads {
		ts.writeError(w, http.StatusForbidden, "Downloads disabled", "Download functionality is disabled")
		return
	}

	vars := mux.Vars(r)
	infoHash := vars["hash"]

	if len(infoHash) != 40 {
		ts.writeError(w, http.StatusBadRequest, "Invalid info hash", "Info hash must be 40 characters")
		return
	}

	// Check if we have the torrent file cached
	torrentPath := filepath.Join(ts.config.CacheDir, infoHash+".torrent")

	// Try to serve from cache first
	if data, err := os.ReadFile(torrentPath); err == nil {
		w.Header().Set("Content-Type", "application/x-bittorrent")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.torrent\"", infoHash))
		w.Write(data)
		return
	}

	ts.writeError(w, http.StatusNotFound, "Torrent file not found", "Torrent file not available in cache")
}

func (ts *TorrentService) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status": "ok",
		"stats": map[string]interface{}{
			"active_torrents": len(ts.client.Torrents()),
			"cache_dir":       ts.config.CacheDir,
			"seeding_enabled": ts.config.SeedingEnabled,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func (ts *TorrentService) writeError(w http.ResponseWriter, status int, error, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:   error,
		Message: message,
	})
}

func (ts *TorrentService) setupRoutes() *mux.Router {
	r := mux.NewRouter()

	// API routes
	api := r.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/metadata", ts.handleGetMetadata).Methods("POST")
	api.HandleFunc("/health", ts.handleHealth).Methods("GET")

	// Download route (if enabled)
	if ts.config.EnableDownloads {
		r.HandleFunc("/download/{hash}", ts.handleDownload).Methods("GET")
	}

	// Middleware
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			log.Printf("%s %s", r.Method, r.URL.Path)
			next.ServeHTTP(w, r)
		})
	})

	return r
}

func main() {
	config := LoadConfig()

	log.Printf("Starting Torrent Metadata API Service")
	log.Printf("Config: Port=%s, CacheDir=%s, EnableDownloads=%v, SeedingEnabled=%v",
		config.Port, config.CacheDir, config.EnableDownloads, config.SeedingEnabled)

	service, err := NewTorrentService(config)
	if err != nil {
		log.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	router := service.setupRoutes()

	log.Printf("Server listening on port %s", config.Port)
	if err := http.ListenAndServe(":"+config.Port, router); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
