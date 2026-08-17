// Package migrations owns InboxGate's immutable, embedded schema catalog.
package migrations

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	MaximumCount      = 256
	MaximumFileBytes  = 256 << 10
	MaximumTotalBytes = 4 << 20
)

var (
	ErrInvalidCatalog = errors.New("migrations: invalid catalog")
	canonicalName     = regexp.MustCompile(`^([0-9]{4})_([a-z][a-z0-9]*(?:_[a-z0-9]+)*)\.sql$`)

	//go:embed *.sql
	embedded embed.FS
)

// Migration is one validated, immutable catalog entry.
//
// SQL contains only repository-reviewed embedded bytes.
type Migration struct {
	Number   uint16
	Name     string
	Checksum string
	SQL      string
}

// Catalog returns a fresh copy of the validated embedded catalog.
func Catalog() ([]Migration, error) {
	return loadCatalog(embedded)
}

func loadCatalog(source fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(source, ".")
	if err != nil {
		return nil, ErrInvalidCatalog
	}
	if len(entries) == 0 || len(entries) > MaximumCount {
		return nil, ErrInvalidCatalog
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || path.Ext(entry.Name()) != ".sql" {
			return nil, ErrInvalidCatalog
		}
		names = append(names, entry.Name())
	}
	slices.Sort(names)

	catalog := make([]Migration, 0, len(names))
	total := 0
	for index, name := range names {
		matches := canonicalName.FindStringSubmatch(name)
		if matches == nil {
			return nil, ErrInvalidCatalog
		}
		number, err := strconv.Atoi(matches[1])
		if err != nil || number != index+1 || number > MaximumCount {
			return nil, ErrInvalidCatalog
		}
		contents, err := fs.ReadFile(source, name)
		if err != nil || len(contents) == 0 || len(contents) > MaximumFileBytes {
			return nil, ErrInvalidCatalog
		}
		total += len(contents)
		if total > MaximumTotalBytes || !utf8.Valid(contents) || strings.IndexByte(string(contents), 0) >= 0 {
			return nil, ErrInvalidCatalog
		}
		sum := sha256.Sum256(contents)
		catalog = append(catalog, Migration{
			Number:   uint16(number),
			Name:     name,
			Checksum: hex.EncodeToString(sum[:]),
			SQL:      string(contents),
		})
	}
	if catalog[0].Name != "0001_migration_ledger.sql" {
		return nil, ErrInvalidCatalog
	}
	return catalog, nil
}
