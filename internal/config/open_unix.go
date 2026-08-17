//go:build unix

package config

import (
	"os"
	"syscall"
)

func openConfigurationFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
