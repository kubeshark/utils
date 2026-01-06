package baseentrystore

import (
	"fmt"
	"time"

	"github.com/kubeshark/worker/pkg/baseentrystore/badger"
	"github.com/kubeshark/worker/pkg/baseentrystore/pebble"
)

// BackendType represents the type of storage backend
type BackendType string

const (
	// BackendBadger uses BadgerDB as the storage backend
	BackendBadger BackendType = "badger"
	// BackendPebble uses Pebble as the storage backend
	BackendPebble BackendType = "pebble"
)

// NewStore creates a new BaseEntryStore with the specified backend
func NewStore(backend BackendType, path string, maxSize int64, chunkSize uint32) (BaseEntryStore, error) {
	switch backend {
	case BackendBadger:
		return badger.NewBadgerStore(path, maxSize, chunkSize, 1*time.Minute)
	case BackendPebble:
		return pebble.NewPebbleStore(path, maxSize, chunkSize, 1*time.Minute)
	default:
		return nil, fmt.Errorf("unknown storage backend: %s (supported: badger, pebble)", backend)
	}
}

// NewBaseEntryStore creates a new BaseEntryStore using BadgerDB (legacy compatibility)
// Deprecated: Use NewStore with BackendBadger instead
func NewBaseEntryStore(name string, maxDbSize int64, payloadChunkSize uint32) (BaseEntryStore, error) {
	return NewStore(BackendBadger, name, maxDbSize, payloadChunkSize)
}
