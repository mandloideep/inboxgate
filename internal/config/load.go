package config

import (
	"fmt"
	"io"
	"os"
)

func Load(path string) (Config, error) {
	pathInfo, err := os.Stat(path)
	if err != nil {
		return Config{}, validationError(Problem{Path: "file", Reason: "cannot inspect configuration file"})
	}
	if !pathInfo.Mode().IsRegular() {
		return Config{}, validationError(Problem{Path: "file", Reason: "configuration target must be a regular file"})
	}
	file, err := openConfigurationFile(path)
	if err != nil {
		return Config{}, validationError(Problem{Path: "file", Reason: "cannot open configuration file"})
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return Config{}, validationError(Problem{Path: "file", Reason: "cannot inspect configuration file"})
	}
	if !info.Mode().IsRegular() {
		return Config{}, validationError(Problem{Path: "file", Reason: "configuration target must be a regular file"})
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxFileBytes+1))
	if err != nil {
		return Config{}, validationError(Problem{Path: "file", Reason: "cannot read configuration file"})
	}
	if len(data) > MaxFileBytes {
		return Config{}, validationError(Problem{Path: "file", Reason: fmt.Sprintf("configuration exceeds the %d-byte limit", MaxFileBytes)})
	}
	return Parse(data)
}
