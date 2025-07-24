package torrent

import (
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

func (ts *TorrentService) getMetadataFromITorrents(magnetURI string) (*model.TorrentMetadata, error) {
	// Extract info hash from magnet URI
	infoHash, err := extractInfoHashFromMagnet(magnetURI)
	if err != nil {
		return nil, fmt.Errorf("[fallback] failed to extract info hash from magnet URI: %w", err)
	}

	// Convert info hash to uppercase hex format
	infoHashHex := strings.ToUpper(infoHash)

	// Construct iTorrents URL
	torrentURL := fmt.Sprintf("http://itorrents.org/torrent/%s.torrent", infoHashHex)

	// Fetch torrent file
	torrentData, err := fetchTorrentFile(torrentURL)
	if err != nil {
		return nil, fmt.Errorf("[fallback] failed to fetch torrent file: %w", err)
	}

	// Parse torrent file
	metadata, err := parseTorrentFile(torrentData, infoHashHex)
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

// fetchTorrentFile fetches the torrent file from iTorrents with gzip support
func fetchTorrentFile(url string) ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Set headers to accept gzip encoding
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", "TorrentMetadataService/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
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

// parseTorrentFile parses the torrent file data and extracts metadata
func parseTorrentFile(data []byte, infoHash string) (*model.TorrentMetadata, error) {
	var torrent TorrentFile

	err := bencode.DecodeBytes(data, &torrent)
	if err != nil {
		return nil, fmt.Errorf("failed to decode torrent file: %w", err)
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
