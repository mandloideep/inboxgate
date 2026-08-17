//go:build !unix

package config

import "os"

func openConfigurationFile(path string) (*os.File, error) {
	return os.Open(path)
}
