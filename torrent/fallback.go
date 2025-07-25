package torrent

import (
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/felipemarinho97/torrent-2-magnet/model"
	"github.com/zeebo/bencode"
)

// TorrentFile represents the structure of a .torrent file
type TorrentFile struct {
	Announce     string      `bencode:"announce"`
	AnnounceList [][]string  `bencode:"announce-list"`
	Comment      string      `bencode:"comment"`
	CreatedBy    string      `bencode:"created by"`
	CreationDate int64       `bencode:"creation date"`
	Info         TorrentInfo `bencode:"info"`
}

type TorrentInfo struct {
	Name        string            `bencode:"name"`
	Length      int64             `bencode:"length"`
	Files       []TorrentFileInfo `bencode:"files"`
	PieceLength int64             `bencode:"piece length"`
	Pieces      string            `bencode:"pieces"`
}

type TorrentFileInfo struct {
	Length int64    `bencode:"length"`
	Path   []string `bencode:"path"`
}

// Custom decoder that stops when it encounters the pieces field
type PartialTorrentInfo struct {
	Name        string            `bencode:"name"`
	Length      int64             `bencode:"length"`
	Files       []TorrentFileInfo `bencode:"files"`
	PieceLength int64             `bencode:"piece length"`
	// We'll skip the pieces field to avoid downloading large data
}

type PartialTorrentFile struct {
	Announce     string             `bencode:"announce"`
	AnnounceList [][]string         `bencode:"announce-list"`
	Comment      string             `bencode:"comment"`
	CreatedBy    string             `bencode:"created by"`
	CreationDate int64              `bencode:"creation date"`
	Info         PartialTorrentInfo `bencode:"info"`
}

const (
	// Initial chunk size - should be enough for most torrent headers
	initialChunkSize = 12 * 1024 // 12KB
	// Maximum total size we're willing to download
	maxHeaderSize = 512 * 1024 // 512KB
	// Chunk increment size
	chunkIncrement = 16 * 1024 // 16KB
)

func (ts *TorrentService) getMetadataFromITorrents(magnetURI string) (*model.TorrentMetadata, error) {
	hash, err := ts.parseMagnetURI(magnetURI)
	if err != nil {
		fmt.Printf("[fallback] Failed to parse magnet URI: %v\n", err)
		return nil, fmt.Errorf("[fallback] failed to parse magnet URI: %w", err)
	}
	// Extract info hash from magnet URI
	infoHash := hash.String()

	// Convert info hash to uppercase hex format
	infoHashHex := strings.ToUpper(infoHash)

	// Construct iTorrents URL
	torrentURL := fmt.Sprintf("http://itorrents.org/torrent/%s.torrent", infoHashHex)

	// Fetch torrent file header
	torrentData, err := fetchTorrentHeader(torrentURL)
	if err != nil {
		return nil, fmt.Errorf("[fallback] failed to fetch torrent file: %w", err)
	}

	// Parse torrent file
	metadata, err := parsePartialTorrentFile(torrentData, infoHashHex)
	if err != nil {
		return nil, fmt.Errorf("[fallback] failed to parse torrent file: %w", err)
	}

	// Set download URL
	downloadURL := torrentURL
	metadata.DownloadURL = &downloadURL

	// cache the metadata
	if err := ts.cacheMetadata(metadata); err != nil {
		return nil, fmt.Errorf("[fallback] failed to cache metadata: %w", err)
	}

	return metadata, nil
}

// fetchTorrentHeader fetches only the header portion of the torrent file
func fetchTorrentHeader(url string) ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	var allData bytes.Buffer
	currentSize := initialChunkSize
	start := 0

	for currentSize <= maxHeaderSize {
		// Try to fetch current chunk size
		chunk, err := fetchChunk(client, url, start, currentSize-1)
		if err != nil {
			return nil, err
		}

		allData.Write(chunk)

		// Try to parse what we have so far
		if complete, safeData := getCompleteHeader(allData.Bytes()); complete {
			return safeData, nil
		}

		// If we got less data than requested, we've reached the end of file
		if len(chunk) < currentSize {
			fmt.Printf("[fallback] Reached end of file at %d bytes\n", start+len(chunk))
			return allData.Bytes(), nil
		}

		// Increase chunk size and try again
		currentSize += chunkIncrement
		start += len(chunk)
	}

	return nil, fmt.Errorf("torrent header too large (exceeded %d bytes)", maxHeaderSize)
}

// fetchChunk fetches a specific byte range from the URL
func fetchChunk(client *http.Client, url string, start, end int) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Set range header to fetch only specific bytes
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", "TorrentMetadataService/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Accept both 200 (full content) and 206 (partial content)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return nil, fmt.Errorf("HTTP error: %d %s", resp.StatusCode, resp.Status)
	}

	var reader io.Reader = resp.Body

	// Check if response is gzip compressed
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzipReader.Close()
		reader = gzipReader
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return data, nil
}

// getCompleteHeader checks if we have enough data to parse the torrent metadata
// This is a heuristic - we look for the pieces field which comes after all metadata
func getCompleteHeader(data []byte) (bool, []byte) {
	piecesMarker := []byte("pieces")
	piecesIndex := bytes.Index(data, piecesMarker)

	if piecesIndex == -1 {
		return false, nil // Haven't reached "pieces" field yet
	}

	// Truncate to avoid decoding garbage past this point
	safeData := data[:piecesIndex+len(piecesMarker)]

	// append bencode endings
	safeData = append(safeData, []byte("1ee")...) // bencode end marker

	var partial PartialTorrentFile
	_ = bencode.DecodeBytes(safeData, &partial)
	return len(partial.Info.Files) > 0 || partial.Info.Length > 0, safeData
}

// parsePartialTorrentFile parses the torrent file data and extracts metadata (without pieces)
func parsePartialTorrentFile(data []byte, infoHash string) (*model.TorrentMetadata, error) {
	var torrent PartialTorrentFile

	err := bencode.DecodeBytes(data, &torrent)
	if err != nil && torrent.Info.Name == "" {
		// If partial parsing fails, try to extract what we can manually
		return parseManuallyFromBytes(data, infoHash)
	}

	metadata := &model.TorrentMetadata{
		InfoHash: infoHash,
		Name:     torrent.Info.Name,
		Comment:  torrent.Comment,
	}

	// Set creation date if available
	if torrent.CreationDate > 0 {
		createdAt := time.Unix(torrent.CreationDate, 0)
		metadata.CreatedAt = &createdAt
	}

	// Extract trackers
	trackers := []string{}
	if torrent.Announce != "" {
		trackers = append(trackers, torrent.Announce)
	}

	// Add announce-list trackers
	for _, tierList := range torrent.AnnounceList {
		for _, tracker := range tierList {
			if tracker != "" && !contains(trackers, tracker) {
				trackers = append(trackers, tracker)
			}
		}
	}
	metadata.Trackers = trackers

	// Handle files and calculate total size
	var totalSize int64
	var files []model.FileInfo
	var offset int64

	if torrent.Info.Length > 0 {
		// Single file torrent
		totalSize = torrent.Info.Length
		files = []model.FileInfo{
			{
				Path:   torrent.Info.Name,
				Size:   torrent.Info.Length,
				Offset: 0,
			},
		}
	} else {
		// Multi-file torrent
		for _, file := range torrent.Info.Files {
			filePath := filepath.Join(file.Path...)
			files = append(files, model.FileInfo{
				Path:   filePath,
				Size:   file.Length,
				Offset: offset,
			})
			totalSize += file.Length
			offset += file.Length
		}
	}

	metadata.Size = totalSize
	metadata.Files = files

	return metadata, nil
}

// parseManuallyFromBytes attempts to extract metadata when bencode parsing fails
func parseManuallyFromBytes(data []byte, infoHash string) (*model.TorrentMetadata, error) {
	// This is a fallback - try to decode as a regular torrent file
	// but ignore errors related to incomplete pieces data
	var torrent map[string]interface{}
	err := bencode.DecodeBytes(data, &torrent)
	if err != nil {
		return nil, fmt.Errorf("failed to decode torrent data: %w", err)
	}

	metadata := &model.TorrentMetadata{
		InfoHash: infoHash,
	}

	// Extract announce
	if announce, ok := torrent["announce"].(string); ok {
		metadata.Trackers = append(metadata.Trackers, announce)
	}

	// Extract announce-list
	if announceList, ok := torrent["announce-list"].([]interface{}); ok {
		for _, tier := range announceList {
			if tierList, ok := tier.([]interface{}); ok {
				for _, tracker := range tierList {
					if trackerStr, ok := tracker.(string); ok && !contains(metadata.Trackers, trackerStr) {
						metadata.Trackers = append(metadata.Trackers, trackerStr)
					}
				}
			}
		}
	}

	// Extract comment
	if comment, ok := torrent["comment"].(string); ok {
		metadata.Comment = comment
	}

	// Extract creation date
	if creationDate, ok := torrent["creation date"].(int64); ok {
		createdAt := time.Unix(creationDate, 0)
		metadata.CreatedAt = &createdAt
	}

	// Extract info section
	if info, ok := torrent["info"].(map[string]interface{}); ok {
		if name, ok := info["name"].(string); ok {
			metadata.Name = name
		}

		// Handle single file vs multi-file
		if length, ok := info["length"].(int64); ok {
			// Single file torrent
			metadata.Size = length
			metadata.Files = []model.FileInfo{
				{
					Path:   metadata.Name,
					Size:   length,
					Offset: 0,
				},
			}
		} else if files, ok := info["files"].([]interface{}); ok {
			// Multi-file torrent
			var totalSize int64
			var fileInfos []model.FileInfo
			var offset int64

			for _, file := range files {
				if fileMap, ok := file.(map[string]interface{}); ok {
					var fileLength int64
					var filePath []string

					if length, ok := fileMap["length"].(int64); ok {
						fileLength = length
					}

					if pathList, ok := fileMap["path"].([]interface{}); ok {
						for _, pathPart := range pathList {
							if pathStr, ok := pathPart.(string); ok {
								filePath = append(filePath, pathStr)
							}
						}
					}

					if len(filePath) > 0 {
						fileInfos = append(fileInfos, model.FileInfo{
							Path:   filepath.Join(filePath...),
							Size:   fileLength,
							Offset: offset,
						})
						totalSize += fileLength
						offset += fileLength
					}
				}
			}

			metadata.Size = totalSize
			metadata.Files = fileInfos
		}
	}

	return metadata, nil
}

// extractInfoHashFromMagnet extracts the info hash from a magnet URI
func extractInfoHashFromMagnet(magnetURI string) (string, error) {
	// Parse the magnet URI
	u, err := url.Parse(magnetURI)
	if err != nil {
		return "", fmt.Errorf("invalid magnet URI: %w", err)
	}

	if u.Scheme != "magnet" {
		return "", fmt.Errorf("not a magnet URI")
	}

	// Extract xt parameter (exact topic)
	query := u.Query()
	xt := query.Get("xt")
	if xt == "" {
		return "", fmt.Errorf("no xt parameter found in magnet URI")
	}

	// Extract info hash from xt parameter
	// Format is usually "urn:btih:INFO_HASH"
	re := regexp.MustCompile(`urn:btih:([a-fA-F0-9]{40})`)
	matches := re.FindStringSubmatch(xt)
	if len(matches) < 2 {
		return "", fmt.Errorf("invalid xt parameter format")
	}

	return matches[1], nil
}

// contains checks if a string slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Verify info hash by recalculating it from the info section
func verifyInfoHash(data []byte, expectedHash string) error {
	var torrent map[string]interface{}
	err := bencode.DecodeBytes(data, &torrent)
	if err != nil {
		return err
	}

	infoSection, ok := torrent["info"]
	if !ok {
		return fmt.Errorf("no info section found in torrent")
	}

	// Re-encode the info section
	infoBytes, err := bencode.EncodeBytes(infoSection)
	if err != nil {
		return err
	}

	// Calculate SHA1 hash
	hash := sha1.Sum(infoBytes)
	calculatedHash := fmt.Sprintf("%X", hash)

	if calculatedHash != strings.ToUpper(expectedHash) {
		return fmt.Errorf("info hash mismatch: expected %s, got %s", expectedHash, calculatedHash)
	}

	return nil
}
