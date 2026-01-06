package pebble

import (
	"github.com/cockroachdb/pebble"
)

// customDB wraps pebble.DB to provide additional functionality
type customDB struct {
	*pebble.DB
}

// NewCustomDB creates a new custom database instance
func NewCustomDB(opts *pebble.Options, dir string) (*customDB, error) {
	db, err := pebble.Open(dir, opts)
	if err != nil {
		return nil, err
	}

	return &customDB{
		DB: db,
	}, nil
}

// Size returns the current database size from metrics
func (db *customDB) Size() int64 {
	metrics := db.Metrics()
	// return int64(metrics.Total().Size)
	return int64(metrics.DiskSpaceUsage())
}
