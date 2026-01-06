package baseentrystore

import (
	"context"

	v1 "github.com/kubeshark/api2/pkg/proto/capture/v1"
)

// BaseEntryStore provides a high-level interface for storing network capture data
type BaseEntryStore interface {
	// StoreBaseEntry stores the base entry. Creates empty keys for all payloads, pcaps, and time index key.
	StoreBaseEntry(ctx context.Context, entry *v1.BaseEntry) error

	// AddPayload appends a payload of the base entry to given payloadId.
	AddPayload(ctx context.Context, entryId uint64, payloadId uint32, payload []byte) error

	// AddPcap appends a pcap of the base entry.
	AddPcap(ctx context.Context, entryId uint64, pcap []byte) error

	// LoadBaseEntry loads the base entry from the store.
	LoadBaseEntry(ctx context.Context, entryId uint64) (*v1.BaseEntry, error)

	// LoadPayload loads a payload of the base entry of given payloadId from the store at given offset and length.
	// length == -1 means load the entire payload.
	LoadPayload(ctx context.Context, entryId uint64, payloadId uint32, offset uint64, length int64) ([]byte, error)

	// LoadPcap loads a pcap of the base entry from the store at given offset and length.
	// length == -1 means load the entire pcap.
	LoadPcap(ctx context.Context, entryId uint64, offset uint64, length int64) ([]byte, error)

	// ListEntries returns all entry IDs, useful for management operations
	ListEntries(ctx context.Context) ([]uint64, error)

	// GetCurrentSize returns the current database size in bytes
	GetCurrentSize() (lsmSize, vlogSize, realSize int64)

	// Close closes the underlying store and stops background cleanup
	Close() error
}
