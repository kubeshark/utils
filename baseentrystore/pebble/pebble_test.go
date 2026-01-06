package pebble

import (
	"context"
	"fmt"
	"testing"
	"time"

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

// Backend-specific tests that access internal Pebble APIs

func TestLoadBaseEntry_UnmarshalError(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewPebbleStore(tempDir, 0, 1024, 1*time.Minute)
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

	// Corrupt the entry using Pebble's Set directly
	if err := s.db.DB.Set(entryKey(entry.Id), []byte{0xFF, 0x00, 0x01}, nil); err != nil {
		t.Fatalf("failed to corrupt entry value: %v", err)
	}

	if _, err := store.LoadBaseEntry(ctx, entry.Id); err == nil {
		t.Fatalf("expected unmarshal error for corrupted base entry")
	}
}

func TestLoadPayload_MalformedChunkKey_ParseError(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewPebbleStore(tempDir, 0, 4096, 1*time.Minute)
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

	// Insert malformed key using Pebble's Set directly
	bad := []byte(fmt.Sprintf("e:%020d:pd:%010d:%s", entry.Id, payloadId, "abc"))
	if err := s.db.DB.Set(bad, []byte("bad"), nil); err != nil {
		t.Fatalf("failed to insert malformed payload key: %v", err)
	}

	if _, err := store.LoadPayload(ctx, entry.Id, payloadId, 0, -1); err == nil {
		t.Fatalf("expected parse error for malformed payload chunk key")
	}
}

func TestAddPayload_FindLastChunk_ParseError(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewPebbleStore(tempDir, 0, 4096, 1*time.Minute)
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

	// Insert malformed key using Pebble's Set directly
	bad := []byte(fmt.Sprintf("e:%020d:pd:%010d:%s", entry.Id, payloadId, "oops"))
	if err := s.db.DB.Set(bad, []byte("bad"), nil); err != nil {
		t.Fatalf("failed to insert malformed last payload key: %v", err)
	}

	if err := store.AddPayload(ctx, entry.Id, payloadId, []byte("X")); err == nil {
		t.Fatalf("expected error in AddPayload due to malformed last chunk key")
	}
}

func TestLoadPcap_MalformedChunkKey_ParseError(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewPebbleStore(tempDir, 0, 4096, 1*time.Minute)
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

	// Insert malformed key using Pebble's Set directly
	bad := []byte(fmt.Sprintf("e:%020d:pc:%s", entry.Id, "abc"))
	if err := s.db.DB.Set(bad, []byte("bad"), nil); err != nil {
		t.Fatalf("failed to insert malformed pcap key: %v", err)
	}

	if _, err := store.LoadPcap(ctx, entry.Id, 0, -1); err == nil {
		t.Fatalf("expected parse error for malformed pcap chunk key")
	}
}

func TestListEntries_SkipsBadHexKey(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewPebbleStore(tempDir, 0, 1024, 1*time.Minute)
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

	// Insert bad key using Pebble's Set directly
	if err := s.db.DB.Set([]byte("e:not-a-number"), []byte("x"), nil); err != nil {
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
