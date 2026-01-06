package badger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
	v1 "github.com/kubeshark/api2/pkg/proto/capture/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// MemorySnapshot captures memory usage at a specific point
type MemorySnapshot struct {
	Alloc      uint64 // Current allocated memory in bytes
	TotalAlloc uint64 // Cumulative allocated memory
	Sys        uint64 // System memory obtained from OS
	NumGC      uint32 // Number of completed GC cycles
	Timestamp  time.Time
	Label      string
}

// Helper function to create test BaseEntry
func createTestBaseEntry(id uint64, nodeId string) *v1.BaseEntry {
	now := timestamppb.New(time.Now())

	return &v1.BaseEntry{
		Id:        id,
		NodeId:    nodeId,
		Timestamp: now,
	}
}

// Backend-specific tests that access internal BadgerDB APIs

func TestLoadBaseEntry_UnmarshalError(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewBadgerStore(tempDir, 0, 1024, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s := store

	ctx := context.Background()
	entry := createTestBaseEntry(12345, "node")
	if err := store.StoreBaseEntry(ctx, entry); err != nil {
		t.Fatal(err)
	}

	if err := s.db.DB.Update(func(txn *badger.Txn) error {
		return txn.Set(entryKey(entry.Id), []byte{0xFF, 0x00, 0x01})
	}); err != nil {
		t.Fatalf("failed to corrupt entry value: %v", err)
	}

	if _, err := store.LoadBaseEntry(ctx, entry.Id); err == nil {
		t.Fatalf("expected unmarshal error for corrupted base entry")
	}
}

func TestLoadPayload_MalformedChunkKey_ParseError(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewBadgerStore(tempDir, 0, 4096, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s := store

	ctx := context.Background()
	entry := createTestBaseEntry(23456, "node")
	if err := store.StoreBaseEntry(ctx, entry); err != nil {
		t.Fatal(err)
	}
	payloadId := uint32(1)

	if err := s.db.DB.Update(func(txn *badger.Txn) error {
		bad := []byte(fmt.Sprintf("e:%020d:pd:%010d:%s", entry.Id, payloadId, "abc"))
		return txn.Set(bad, []byte("bad"))
	}); err != nil {
		t.Fatalf("failed to insert malformed payload key: %v", err)
	}

	if _, err := store.LoadPayload(ctx, entry.Id, payloadId, 0, -1); err == nil {
		t.Fatalf("expected parse error for malformed payload chunk key")
	}
}

func TestAddPayload_FindLastChunk_ParseError(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewBadgerStore(tempDir, 0, 4096, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s := store

	ctx := context.Background()
	entry := createTestBaseEntry(34567, "node")
	if err := store.StoreBaseEntry(ctx, entry); err != nil {
		t.Fatal(err)
	}
	payloadId := uint32(1)

	if err := s.db.DB.Update(func(txn *badger.Txn) error {
		bad := []byte(fmt.Sprintf("e:%020d:pd:%010d:%s", entry.Id, payloadId, "oops"))
		return txn.Set(bad, []byte("bad"))
	}); err != nil {
		t.Fatalf("failed to insert malformed last payload key: %v", err)
	}

	if err := store.AddPayload(ctx, entry.Id, payloadId, []byte("X")); err == nil {
		t.Fatalf("expected error in AddPayload due to malformed last chunk key")
	}
}

func TestLoadPcap_MalformedChunkKey_ParseError(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewBadgerStore(tempDir, 0, 4096, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s := store

	ctx := context.Background()
	entry := createTestBaseEntry(45678, "node")
	if err := store.StoreBaseEntry(ctx, entry); err != nil {
		t.Fatal(err)
	}

	if err := s.db.DB.Update(func(txn *badger.Txn) error {
		bad := []byte(fmt.Sprintf("e:%020d:pc:%s", entry.Id, "abc"))
		return txn.Set(bad, []byte("bad"))
	}); err != nil {
		t.Fatalf("failed to insert malformed pcap key: %v", err)
	}

	if _, err := store.LoadPcap(ctx, entry.Id, 0, -1); err == nil {
		t.Fatalf("expected parse error for malformed pcap chunk key")
	}
}

func TestListEntries_SkipsBadHexKey(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewBadgerStore(tempDir, 0, 1024, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s := store

	ctx := context.Background()
	good := createTestBaseEntry(56789, "node")
	if err := store.StoreBaseEntry(ctx, good); err != nil {
		t.Fatal(err)
	}

	if err := s.db.DB.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("e:not-a-number"), []byte("x"))
	}); err != nil {
		t.Fatalf("failed to insert bad e: key: %v", err)
	}

	ids, err := store.ListEntries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != good.Id {
		t.Fatalf("expected only the good entry id; got %d ids (first=%d)", len(ids), ids[0])
	}
}

func TestCleanupContextHandling(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewBadgerStore(tempDir, 0, 1024, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	entry := createTestBaseEntry(67890, "node")
	if err := store.StoreBaseEntry(ctx, entry); err != nil {
		t.Fatal(err)
	}
	if err := store.AddPayload(ctx, entry.Id, 1, bytes.Repeat([]byte("a"), 3*1024)); err != nil {
		t.Fatal(err)
	}

	// Test that context cancellation works during iteration
	// This is a simplified test since we removed deleteBaseEntry function
	cctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Try to list entries with canceled context
	_, err = store.ListEntries(cctx)
	if err == nil {
		t.Fatalf("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected wrapped context.Canceled, got: %v", err)
	}
}

func TestStoreBaseEntry_DBClosed_Error(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewBadgerStore(tempDir, 0, 1024, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()

	ctx := context.Background()
	entry := createTestBaseEntry(78901, "node")
	if err := store.StoreBaseEntry(ctx, entry); err == nil {
		t.Fatalf("expected error when storing with closed DB")
	}
}

// Badger-specific helper function test
func TestLowerPowerOf2_Edges(t *testing.T) {
	const minSize int64 = 1 << 20
	const maxSize int64 = 2<<30 - 1

	if got := lowerPowerOf2(-1); got != 0 {
		t.Fatalf("lowerPowerOf2(-1) = %d, want 0", got)
	}
	if got := lowerPowerOf2(0); got != maxSize {
		t.Fatalf("lowerPowerOf2(0) = %d, want %d", got, maxSize)
	}
	if got := lowerPowerOf2(500_000); got != minSize {
		t.Fatalf("lowerPowerOf2(500000) = %d, want %d (minSize)", got, minSize)
	}
	if got := lowerPowerOf2(1 << 40); got != maxSize/2 {
		t.Fatalf("lowerPowerOf2(1<<40) = %d, want %d (1GB cap)", got, maxSize/2)
	}
}
