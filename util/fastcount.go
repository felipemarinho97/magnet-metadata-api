package util

import (
	"fmt"
	"os"
)

func CountDir(dir string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var count int64

	for _, entry := range entries {
		name := entry.Name()
		if len(name) > 5 && name[len(name)-5:] == ".json" {
			count++
		}
	}

	return count, nil
}
