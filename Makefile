build:
	docker build -t magnet-metadata-api .

lint:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run -v --timeout 5m

lint-fix:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run -v --fix --timeout 5m

run:	