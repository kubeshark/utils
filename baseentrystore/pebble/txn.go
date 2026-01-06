package pebble

// customTxn is a wrapper around pebble operations that provides transaction-like semantics.
//
// Why custom transaction wrapper is required:
// - Provides a consistent interface for batch operations across the codebase
// - Supports NoSync mode for cleanup operations to maximize performance during bulk deletions
// - Wraps pebble.Batch to provide additional functionality like Get() and NewIter()
//
// How it works:
// - Wraps pebble.Batch for write operations (Set, Delete, DeleteRange)
// - Provides read operations (Get, NewIter) that query the underlying DB
// - Supports both Sync and NoSync write modes for different performance characteristics

import (
	"fmt"

	"github.com/cockroachdb/pebble"
)

// customTxn wraps pebble.Batch to provide transaction-like operations
type customTxn struct {
	batch  *pebble.Batch
	store  *baseEntryStore
	db     *customDB
	noSync bool // If true, use NoSync for write operations (for cleanup performance)
}

// Set wraps the batch Set method
func (txn *customTxn) Set(key, val []byte) error {
	// Default to NoSync for performance - periodic sync worker handles durability
	writeOpts := pebble.NoSync
	if txn.noSync {
		writeOpts = pebble.NoSync
	}

	return txn.batch.Set(key, val, writeOpts)
}

// Delete wraps the batch Delete method
func (txn *customTxn) Delete(key []byte) error {
	// Default to NoSync for performance - periodic sync worker handles durability
	writeOpts := pebble.NoSync
	if txn.noSync {
		writeOpts = pebble.NoSync
	}

	return txn.batch.Delete(key, writeOpts)
}

// Get retrieves a value from the database (not the batch)
func (txn *customTxn) Get(key []byte) ([]byte, error) {
	val, closer, err := txn.db.Get(key)
	if err != nil {
		return nil, err
	}
	defer closer.Close()

	// Copy the value since closer will be called
	result := make([]byte, len(val))
	copy(result, val)
	return result, nil
}

// NewIter creates a new iterator with the given options
// Note: Pebble's NewIter can return an error, but in practice it rarely does
// We panic on error here to maintain API compatibility with the test code
func (txn *customTxn) NewIter(opts *pebble.IterOptions) *pebble.Iterator {
	iter, err := txn.db.NewIter(opts)
	if err != nil {
		panic(fmt.Sprintf("pebble NewIter failed: %v", err))
	}
	return iter
}

// DeleteRange deletes a range of keys [start, end)
func (txn *customTxn) DeleteRange(start, end []byte) error {
	// Default to NoSync for performance - periodic sync worker handles durability
	writeOpts := pebble.NoSync
	if txn.noSync {
		writeOpts = pebble.NoSync
	}

	if err := txn.batch.DeleteRange(start, end, writeOpts); err != nil {
		return err
	}

	// Note: We don't track size for DeleteRange as it would require scanning the range
	// During cleanup, size tracking is disabled anyway
	return nil
}

// Commit commits the batch
func (txn *customTxn) Commit() error {
	// Default to NoSync for performance - periodic sync worker handles durability
	writeOpts := pebble.NoSync
	if txn.noSync {
		writeOpts = pebble.NoSync
	}
	return txn.batch.Commit(writeOpts)
}

// Close closes the batch
func (txn *customTxn) Close() error {
	return txn.batch.Close()
}

// newCustomTxn creates a new custom transaction (batch)
func (s *baseEntryStore) newCustomTxn(update bool) *customTxn {
	// Pebble doesn't have read-only transactions, but we use batches for atomicity
	batch := s.db.NewBatch()
	return &customTxn{
		batch: batch,
		store: s,
		db:    s.db,
	}
}

// update creates a new batch and executes the given function
func (s *baseEntryStore) update(fn func(txn *customTxn) error) error {
	txn := s.newCustomTxn(true)
	defer txn.Close()

	if err := fn(txn); err != nil {
		return err
	}
	return txn.Commit()
}

// view creates a new "read-only" transaction and executes the given function
// Note: Pebble doesn't have true read-only transactions, but we use this for consistency
func (s *baseEntryStore) view(fn func(txn *customTxn) error) error {
	txn := s.newCustomTxn(false)
	defer txn.Close()
	return fn(txn)
}
