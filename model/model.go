package model

import (
	"time"
)

// TorrentMetadata represents the metadata of a torrent.
type TorrentMetadata struct {
	InfoHash    string     `json:"info_hash"`
	Name        string     `json:"name"`
	Size        int64      `json:"size"`
	Files       []FileInfo `json:"files"`
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
