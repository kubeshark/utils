package badger

// customTxn is a wrapper around badger.Txn that provides real-time database size tracking.
//
// Why custom transaction wrapper is required:
// - BadgerDB doesn't provide real-time size tracking out of the box
// - We need to track the amount of data added and deleted for cleanup decisions
// - The cleanup process needs to know current DB size to determine when to stop deleting entries
// - BadgerDB's native Size() method is expensive and not suitable for frequent calls
//
// How it works:
// - Intercepts Set() calls to add key+value size to the tracked total
// - Intercepts Delete() calls to subtract key+value size from the tracked total
// - Maintains a running total in customDB.dbSize with atomic updates
//
// Limitations (not robust but simple approach):
// - Size tracking can drift from actual size due to compaction, value log GC, etc.
// - Doesn't account for BadgerDB's internal overhead and metadata
// - No periodic synchronization with actual DB size
// - Relies on accurate size calculation during Set/Delete operations
// - May not reflect the true on-disk size due to compression and fragmentation
//
// This approach trades accuracy for simplicity and performance, providing "good enough"
// size estimates for cleanup decisions without the overhead of frequent Size() calls.

import (
	"github.com/dgraph-io/badger/v4"
)

// customTxn wraps badger.Txn to provide additional functionality
type customTxn struct {
	*badger.Txn
	store *baseEntryStore
	db    *customDB
}

// Set wraps the original Set method to provide additional functionality
func (txn *customTxn) Set(key, val []byte) error {
	if err := txn.Txn.Set(key, val); err != nil {
		return err
	}

	// Update size tracking in the DB
	txn.db.updateSize(int64(len(key) + len(val)))
	return nil
}

// Delete wraps the original Delete method to provide additional functionality
func (txn *customTxn) Delete(key []byte) error {
	// Get the value size before deleting
	var valueSize int
	if item, err := txn.Get(key); err == nil {
		valueSize = int(item.ValueSize())
	}

	if err := txn.Txn.Delete(key); err != nil {
		return err
	}

	// Update size tracking in the DB
	txn.db.updateSize(-int64(len(key) + valueSize))
	return nil
}

// Get wraps the original Get method to provide additional functionality
func (txn *customTxn) Get(key []byte) (*badger.Item, error) {
	return txn.Txn.Get(key)
}

// NewIterator wraps the original NewIterator method to provide additional functionality
func (txn *customTxn) NewIterator(opt badger.IteratorOptions) *badger.Iterator {
	// Having prefetching values is not needed for our use case,
	// Remove this if we decide to support prefetching values:
	opt.PrefetchValues = false

	return txn.Txn.NewIterator(opt)
}

// newCustomTxn creates a new custom transaction
func (s *baseEntryStore) newCustomTxn(update bool) *customTxn {
	return &customTxn{
		Txn:   s.db.DB.NewTransaction(update),
		store: s,
		db:    s.db,
	}
}

// update creates a new update transaction and executes the given function
func (s *baseEntryStore) update(fn func(txn *customTxn) error) error {
	txn := s.newCustomTxn(true)
	defer txn.Discard()

	if err := fn(txn); err != nil {
		return err
	}
	return txn.Commit()
}

// view creates a new read-only transaction and executes the given function
func (s *baseEntryStore) view(fn func(txn *customTxn) error) error {
	txn := s.newCustomTxn(false)
	defer txn.Discard()
	return fn(txn)
}
