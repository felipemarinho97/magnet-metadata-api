package torrent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anacrolix/dht/v2"
	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/felipemarinho97/magnet-metadata-api/config"
	"github.com/felipemarinho97/magnet-metadata-api/model"
	"github.com/felipemarinho97/magnet-metadata-api/util"
	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
)

type TorrentService struct {
	config      *config.Config
	client      *torrent.Client
	redisClient *redis.Client
	ctx         context.Context
	fileCount   int64

	// Lock mechanism for preventing concurrent requests for same hash
	hashLocks  map[string]*sync.Mutex
	lockMapMux sync.RWMutex
}

func NewTorrentService(config *config.Config) (*TorrentService, error) {
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
	clientConfig.DhtStartingNodes = func(network string) dht.StartingNodesGetter {
		return func() ([]dht.Addr, error) {
			nodes := make([]dht.Addr, len(config.DHTPeers))
			for i, peer := range config.DHTPeers {
				port, err := strconv.Atoi(strings.Split(peer, ":")[1])
				if err != nil {
					return nil, fmt.Errorf("invalid DHT peer port: %w", err)
				}
				nodes[i] = dht.NewAddr(&net.TCPAddr{
					IP:   net.ParseIP(strings.Split(peer, ":")[0]),
					Port: port,
				})
			}
			return nodes, nil
		}
	}

	// Additional settings to prevent downloading
	clientConfig.DisableAggressiveUpload = true
	clientConfig.DisableAcceptRateLimiting = true

	client, err := torrent.NewClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create torrent client: %w", err)
	}

	fileCount, err := util.CountDir(config.CacheDir)
	if err != nil {
		fmt.Printf("Warning: Failed to count cached files: %v. Using 0 as initial count.", err)
		fileCount = 0
	}

	// update fileCount every 10 minutes
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			count, err := util.CountDir(config.CacheDir)
			if err != nil {
				log.Printf("Warning: Failed to update cached file count: %v", err)
			} else {
				fileCount = count
				log.Printf("Updated cached file count: %d", fileCount)
			}
		}
	}()

	initialChunkSizeStr := os.Getenv("FALLBACK_INITIAL_CHUNK_SIZE_KB")
	if initialChunkSizeStr != "" {
		if size, err := strconv.Atoi(initialChunkSizeStr); err == nil && size > 0 {
			initialChunkSize = size * 1024 // Convert to bytes
		} else {
			log.Printf("Invalid FALLBACK_INITIAL_CHUNK_SIZE_KB value: %s, using default", initialChunkSize/1024)
		}
	}

	service := &TorrentService{
		config:      config,
		client:      client,
		redisClient: redisClient,
		ctx:         ctx,
		fileCount:   fileCount,
		hashLocks:   make(map[string]*sync.Mutex),
		lockMapMux:  sync.RWMutex{},
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

// getOrCreateHashLock returns a lock for the given hash, creating one if it doesn't exist
func (ts *TorrentService) getOrCreateHashLock(infoHash string) *sync.Mutex {
	ts.lockMapMux.RLock()
	if lock, exists := ts.hashLocks[infoHash]; exists {
		ts.lockMapMux.RUnlock()
		return lock
	}
	ts.lockMapMux.RUnlock()

	// Need to create a new lock
	ts.lockMapMux.Lock()
	defer ts.lockMapMux.Unlock()

	// Double-check in case another goroutine created it while we were waiting
	if lock, exists := ts.hashLocks[infoHash]; exists {
		return lock
	}

	// Create new lock
	lock := &sync.Mutex{}
	ts.hashLocks[infoHash] = lock
	return lock
}

// cleanupHashLock removes the lock for a hash if it's no longer needed
func (ts *TorrentService) cleanupHashLock(infoHash string) {
	ts.lockMapMux.Lock()
	defer ts.lockMapMux.Unlock()

	// Only delete if no one is waiting on it
	if lock, exists := ts.hashLocks[infoHash]; exists {
		// Try to acquire the lock immediately to see if anyone is waiting
		if lock.TryLock() {
			delete(ts.hashLocks, infoHash)
			lock.Unlock()
		}
	}
}

func (ts *TorrentService) parseMagnetURI(magnetURI string) (metainfo.Hash, error) {
	magnet, err := metainfo.ParseMagnetUri(magnetURI)
	if err != nil {
		return metainfo.Hash{}, fmt.Errorf("failed to parse magnet URI: %w", err)
	}

	infoHash := magnet.InfoHash

	return infoHash, nil
}

func (ts *TorrentService) getCachedMetadata(infoHash string) (*model.TorrentMetadata, error) {
	// Try Redis cache first
	if ts.redisClient != nil {
		key := strings.ToLower("metadata:" + infoHash)
		cached, err := ts.redisClient.Get(ts.ctx, key).Result()
		if err == nil {
			var metadata model.TorrentMetadata
			if err := json.Unmarshal([]byte(cached), &metadata); err == nil {
				return &metadata, nil
			}
		}
	}

	// Try disk cache
	cachePath := filepath.Join(ts.config.CacheDir, infoHash+".json")
	if data, err := os.ReadFile(cachePath); err == nil {
		var metadata model.TorrentMetadata
		if err := json.Unmarshal(data, &metadata); err == nil {
			return &metadata, nil
		}
	}

	return nil, nil
}

func (ts *TorrentService) cacheMetadata(metadata *model.TorrentMetadata) error {
	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	// Cache in Redis with 24h expiration
	if ts.redisClient != nil {
		key := strings.ToLower("metadata:" + metadata.InfoHash)
		ts.redisClient.Set(ts.ctx, key, data, 24*time.Hour)
	}

	// Cache on disk
	cachePath := filepath.Join(ts.config.CacheDir, metadata.InfoHash+".json")
	return os.WriteFile(cachePath, data, 0644)
}

func (ts *TorrentService) saveTorrentFile(t *torrent.Torrent, infoHashStr string) error {
	// Save the .torrent file to cache
	torrentPath := filepath.Join(ts.config.CacheDir, infoHashStr+".torrent")

	// Get the metainfo and write to file
	metainfo := t.Metainfo()
	var buf bytes.Buffer
	err := metainfo.Write(&buf)
	torrentData := buf.Bytes()
	if err != nil {
		return fmt.Errorf("failed to marshal torrent file: %w", err)
	}

	return os.WriteFile(torrentPath, torrentData, 0644)
}

func (ts *TorrentService) getTorrentMetadata(ctx context.Context, magnetURI string) (*model.TorrentMetadata, error) {
	infoHash, err := ts.parseMagnetURI(magnetURI)
	if err != nil {
		return nil, err
	}

	infoHashStr := infoHash.String()

	log.Printf("Fetching metadata for info hash: %s", infoHashStr)

	// Check if torrent is already added to client
	existingTorrent, exists := ts.client.Torrent(infoHash)
	if exists && existingTorrent.Info() != nil {
		log.Printf("Torrent already exists in client with info: %s", infoHashStr)
		return ts.extractMetadataFromTorrent(existingTorrent, infoHashStr)
	}

	// Add torrent to client
	t, err := ts.client.AddMagnet(magnetURI)
	if err != nil {
		return nil, fmt.Errorf("failed to add magnet: %w", err)
	}

	// Ensure we clean up the torrent when done
	defer func() {
		// Only drop if we added it and it's not needed anymore
		if t != nil {
			log.Printf("Dropping torrent from client: %s", infoHashStr)
			t.Drop()
		}
	}()

	t.DisallowDataDownload()

	// Wait for info with timeout
	select {
	case <-t.GotInfo():
		log.Printf("Got info for torrent: %s", t.Name())
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("timeout waiting for torrent info")
	case <-ctx.Done():
		return nil, fmt.Errorf("context cancelled while waiting for torrent info")
	}

	return ts.extractMetadataFromTorrent(t, infoHashStr)
}

// extractMetadataFromTorrent extracts metadata from a torrent object
func (ts *TorrentService) extractMetadataFromTorrent(t *torrent.Torrent, infoHashStr string) (*model.TorrentMetadata, error) {
	// Extract metadata
	info := t.Info()
	if info == nil {
		return nil, fmt.Errorf("failed to get torrent info")
	}

	files := make([]model.FileInfo, len(info.Files))
	var offset int64
	for i, file := range info.Files {
		files[i] = model.FileInfo{
			Path:   strings.Join(file.Path, "/"),
			Size:   file.Length,
			Offset: offset,
		}
		offset += file.Length
	}
	// Sort files by size (descending)
	sort.Slice(files, func(i, j int) bool {
		return files[i].Size > files[j].Size
	})

	metadata := &model.TorrentMetadata{
		InfoHash: infoHashStr,
		Name:     info.Name,
		Size:     info.TotalLength(),
		Files:    files,
		Comment:  t.Metainfo().Comment,
	}

	if !(t.Metainfo().CreationDate == 0) {
		timeParsed := time.Unix(t.Metainfo().CreationDate, 0)
		metadata.CreatedAt = &timeParsed
	}

	// Extract trackers
	for _, tier := range t.Metainfo().AnnounceList {
		metadata.Trackers = append(metadata.Trackers, tier...)
	}

	// Add download URL if enabled
	if ts.config.EnableDownloads {
		downloadURL := fmt.Sprintf("/download/%s", infoHashStr)
		metadata.DownloadURL = &downloadURL
	} else {
		metadata.DownloadURL = nil
	}

	// Save the .torrent file before returning
	if err := ts.saveTorrentFile(t, infoHashStr); err != nil {
		log.Printf("Failed to save torrent file: %v", err)
	}

	// Cache the metadata
	if err := ts.cacheMetadata(metadata); err != nil {
		log.Printf("Failed to cache metadata: %v", err)
	}

	return metadata, nil
}

func (ts *TorrentService) handleGetMetadata(w http.ResponseWriter, r *http.Request) {
	var req model.MagnetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ts.writeError(w, http.StatusBadRequest, "Invalid JSON", err.Error())
		return
	}

	if req.MagnetURI == "" {
		ts.writeError(w, http.StatusBadRequest, "Missing magnet URI", "magnet_uri field is required")
		return
	}

	// Parse magnet URI to get info hash early
	infoHash, err := ts.parseMagnetURI(req.MagnetURI)
	if err != nil {
		ts.writeError(w, http.StatusBadRequest, "Invalid magnet URI", err.Error())
		return
	}

	infoHashStr := infoHash.String()

	// Get or create a lock for this specific hash to prevent duplicate scraping
	hashLock := ts.getOrCreateHashLock(infoHashStr)

	// Acquire the lock for this hash
	hashLock.Lock()
	defer func() {
		hashLock.Unlock()
		// Clean up the lock if possible (non-blocking)
		go ts.cleanupHashLock(infoHashStr)
	}()

	log.Printf("Acquired lock for request processing: %s", infoHashStr)

	// Check cache after acquiring lock (another request might have filled it)
	if cached, err := ts.getCachedMetadata(infoHashStr); cached != nil && err == nil {
		log.Printf("Cache hit after lock acquisition for info hash: %s", infoHashStr)
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(cached)
		if err != nil {
			log.Printf("Error encoding cached metadata: %v", err)
			ts.writeError(w, http.StatusInternalServerError, "Encoding error", "Failed to encode cached metadata")
		}
		return
	}

	log.Printf("Cache miss after lock acquisition, proceeding with scraping: %s", infoHashStr)

	type result struct {
		metadata any
		err      error
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	resultCh := make(chan result, 2)

	go func() {
		metadata, err := ts.getTorrentMetadata(ctx, infoHashStr)
		select {
		case resultCh <- result{metadata, err}:
		case <-ctx.Done():
		}
	}()

	go func() {
		metadata, err := ts.getMetadataFromITorrents(infoHashStr)
		select {
		case resultCh <- result{metadata, err}:
		case <-ctx.Done():
		}
	}()

	var lastErr error
	for i := 0; i < 2; i++ {
		select {
		case res := <-resultCh:
			if res.err == nil {
				w.Header().Set("Content-Type", "application/json")
				err = json.NewEncoder(w).Encode(res.metadata)
				if err != nil {
					log.Printf("Error encoding metadata: %v", err)
					ts.writeError(w, http.StatusInternalServerError, "Encoding error", "Failed to encode metadata")
				}
				return
			}
			log.Printf("Error retrieving metadata: %v", res.err)
			lastErr = res.err
		case <-ctx.Done():
			ts.writeError(w, http.StatusGatewayTimeout, "Timeout", "Timeout while retrieving metadata")
			return
		}
	}

	ts.writeError(w, http.StatusInternalServerError, "Failed to get torrent metadata", lastErr.Error())
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
		_, err := w.Write(data)
		if err != nil {
			log.Printf("Error writing torrent file: %v", err)
			ts.writeError(w, http.StatusInternalServerError, "Write error", "Failed to write torrent file")
		}
		return
	}

	ts.writeError(w, http.StatusNotFound, "Torrent file not found", "Torrent file not available in cache")
}

func (ts *TorrentService) handleHealth(w http.ResponseWriter, r *http.Request) {
	ts.lockMapMux.RLock()
	activeLocks := len(ts.hashLocks)
	ts.lockMapMux.RUnlock()

	health := map[string]interface{}{
		"status": "ok",
		"stats": map[string]interface{}{
			"active_torrents": len(ts.client.Torrents()) + int(ts.fileCount),
			"active_locks":    activeLocks,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(health)
	if err != nil {
		log.Printf("Error encoding health response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func (ts *TorrentService) writeError(w http.ResponseWriter, status int, error, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(model.ErrorResponse{
		Error:   error,
		Message: message,
	})
	if err != nil {
		log.Printf("Error encoding error response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func (ts *TorrentService) SetupRoutes() *mux.Router {
	r := mux.NewRouter()

	// API routes
	api := r.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/metadata", ts.handleGetMetadata).Methods("POST")
	api.HandleFunc("/health", ts.handleHealth).Methods("GET")

	// Download route (if enabled)
	if ts.config.EnableDownloads {
		r.HandleFunc("/download/{hash}", ts.handleDownload).Methods("GET")
	}

	// Serve static files from /web at root path
	fs := http.FileServer(http.Dir("web"))
	r.PathPrefix("/").Handler(fs)

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
