package baseentrystore

import "errors"

var (
	// ErrKeyNotFound is returned when a requested key doesn't exist in the store
	ErrKeyNotFound = errors.New("key not found")

	// ErrStoreClosed is returned when attempting to use a closed store
	ErrStoreClosed = errors.New("store is closed")

	// ErrInvalidKey is returned when a key is empty or invalid
	ErrInvalidKey = errors.New("invalid key")

	// ErrContextCanceled is returned when context is canceled
	ErrContextCanceled = errors.New("context canceled")
)
