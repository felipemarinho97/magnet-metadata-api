# Torrent Metadata API Service

A high-performance Go API service that retrieves torrent metadata from magnet links using DHT/peer networks, implements intelligent caching, and participates in the BitTorrent ecosystem as a good peer.

## Features

- **Magnet Link Processing**: Parse and extract metadata from magnet URIs
- **DHT Integration**: Connect to BitTorrent DHT network to fetch torrent information
- **Dual Caching Strategy**: Redis for fast access + disk cache for persistence
- **P2P Network Participation**: Acts as a seeding peer to give back to the network
- **Optional Download Links**: Generate download URLs for cached torrents
- **RESTful API**: Clean HTTP API with comprehensive error handling
- **Containerized**: Docker support with health checks
- **Configurable**: Environment-based configuration
- **Production Ready**: Proper logging, metrics, and graceful shutdown

## Quick Start

### Using Docker Compose (Recommended)

```bash
git clone <repository>
cd torrent-metadata-api
docker-compose up -d
```

### Manual Installation

1. **Prerequisites**:
   ```bash
   go version  # Requires Go 1.21+
   redis-server --version  # Optional but recommended
   ```

2. **Install Dependencies**:
   ```bash
   go mod download
   ```

3. **Run the Service**:
   ```bash
   go run main.go
   ```

## API Endpoints

### POST `/api/v1/metadata`
Retrieve torrent metadata from a magnet link.

**Request Body**:
```json
{
  "magnet_uri": "magnet:?xt=urn:btih:HASH&dn=Name&tr=tracker1&tr=tracker2"
}
```

**Response**:
```json
{
  "info_hash": "abcd1234567890abcdef1234567890abcdef1234",
  "name": "Example Torrent",
  "size": 1073741824,
  "files": [
    {
      "path": "folder/file1.txt",
      "size": 1024,
      "offset": 0
    },
    {
      "path": "folder/file2.txt", 
      "size": 2048,
      "offset": 1024
    }
  ],
  "created_by": "uTorrent/3.5.5",
  "created_at": "2024-01-15T10:30:00Z",
  "comment": "Example torrent comment",
  "trackers": [
    "http://tracker1.example.com:8080/announce",
    "http://tracker2.example.com:8080/announce"
  ],
  "download_url": "http://localhost:8080/download/abcd1234567890abcdef1234567890abcdef1234"
}
```

### GET `/api/v1/health`
Service health check and statistics.

**Response**:
```json
{
  "status": "ok",
  "stats": {
    "active_torrents": 5,
    "cache_dir": "./cache",
    "seeding_enabled": true
  }
}
```

### GET `/download/{hash}` (Optional)
Download cached torrent file. Only available when `ENABLE_DOWNLOADS=true`.

**Response**: Binary torrent file with appropriate headers.

## Configuration

All configuration is done via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP server port |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection URL |
| `CACHE_DIR` | `./cache` | Directory for disk cache storage |
| `ENABLE_DOWNLOADS` | `false` | Enable torrent file downloads |
| `DOWNLOAD_BASE_URL` | `http://localhost:8080` | Base URL for download links |
| `CLIENT_PORT` | `42069` | BitTorrent client port |
| `SEEDING_ENABLED` | `true` | Participate in seeding torrents |

### Example Configuration

```bash
export PORT=9000
export REDIS_URL=redis://redis-server:6379/1
export CACHE_DIR=/var/cache/torrents
export ENABLE_DOWNLOADS=true
export DOWNLOAD_BASE_URL=https://my-domain.com
export SEEDING_ENABLED=true
```

## Caching Strategy

The service implements a two-tier caching system:

1. **Redis Cache** (L1): Fast in-memory cache with 24-hour TTL
2. **Disk Cache** (L2): Persistent storage for torrent metadata and files

### Cache Behavior

- Metadata is cached in both Redis and disk
- Cache keys use