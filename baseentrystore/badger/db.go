package badger

import (
	"sync"

	"github.com/dgraph-io/badger/v4"
)

// customDB wraps badger.DB to provide additional functionality
type customDB struct {
	*badger.DB
	dbSize   int64 // tracks total size of data in bytes
	sizeLock sync.RWMutex
}

// NewCustomDB creates a new custom database instance
func NewCustomDB(opts badger.Options) (*customDB, error) {
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}

	// Get initial size
	lsmSize, vlogSize := db.Size()
	initialSize := lsmSize + vlogSize

	return &customDB{
		DB:     db,
		dbSize: initialSize,
	}, nil
}

// Update wraps the original Update method to use customTxn
func (db *customDB) Update(fn func(txn *badger.Txn) error) error {
	txn := db.NewTransaction(true)
	defer txn.Discard()

	if err := fn(txn); err != nil {
		return err
	}
	return txn.Commit()
}

// View wraps the original View method to use customTxn
func (db *customDB) View(fn func(txn *badger.Txn) error) error {
	txn := db.NewTransaction(false)
	defer txn.Discard()
	return fn(txn)
}

// NewTransaction wraps the original NewTransaction method
func (db *customDB) NewTransaction(update bool) *badger.Txn {
	return db.DB.NewTransaction(update)
}

// GetSize returns the current tracked size of the database
func (db *customDB) GetSize() int64 {
	db.sizeLock.RLock()
	defer db.sizeLock.RUnlock()
	return db.dbSize
}

// updateSize atomically updates the size by delta bytes
func (db *customDB) updateSize(delta int64) {
	db.sizeLock.Lock()
	db.dbSize += delta
	db.sizeLock.Unlock()
}

/*
// SyncSize synchronizes the tracked size with actual DB size
func (db *customDB) SyncSize() {
	lsmSize, vlogSize := db.DB.Size()
	db.sizeLock.Lock()
	db.dbSize = lsmSize + vlogSize
	db.sizeLock.Unlock()
}
*/
