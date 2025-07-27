# Build stage
FROM golang:1.24-alpine AS builder

# Install git and ca-certificates (needed for fetching dependencies and HTTPS)
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o torrent-metadata-api .

# Final stage
FROM alpine:latest
LABEL maintainer="felipevm97@gmail.com"

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN adduser -D -s /bin/sh torrent

WORKDIR /home/torrent

# Copy binary from builder stage
COPY --from=builder /app/torrent-metadata-api .

# Copy static web files
COPY --from=builder /app/web ./web

# Create cache directory
RUN mkdir -p ./cache && chown torrent:torrent ./cache

# Switch to non-root user
USER torrent

# Expose ports
EXPOSE 8080 42069

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/v1/health || exit 1

# Run the application
CMD ["./torrent-metadata-api"]