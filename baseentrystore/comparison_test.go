package baseentrystore

import (
	"context"
	"runtime"
	"testing"
	"time"

	v1 "github.com/kubeshark/api2/pkg/proto/capture/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// MemoryStats captures memory usage statistics
type MemoryStats struct {
	Alloc      uint64
	TotalAlloc uint64
	Sys        uint64
	NumGC      uint32
}

func getMemoryStats() MemoryStats {
	runtime.GC() // Force GC for accurate measurement
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return MemoryStats{
		Alloc:      m.Alloc,
		TotalAlloc: m.TotalAlloc,
		Sys:        m.Sys,
		NumGC:      m.NumGC,
	}
}

func createBenchEntry(id uint64, timestamp time.Time) *v1.BaseEntry {
	return &v1.BaseEntry{
		Id:        id,
		NodeId:    "test-node",
		Timestamp: timestamppb.New(timestamp),
	}
}

// BenchmarkBadgerWrites tests Badger write performance
func BenchmarkBadgerWrites(b *testing.B) {
	tempDir := b.TempDir()
	store, err := NewStore(BackendBadger, tempDir, 0, 4096)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		entry := createBenchEntry(uint64(i), time.Now())
		if err := store.StoreBaseEntry(ctx, entry); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPebbleWrites tests Pebble write performance
func BenchmarkPebbleWrites(b *testing.B) {
	tempDir := b.TempDir()
	store, err := NewStore(BackendPebble, tempDir, 0, 4096)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		entry := createBenchEntry(uint64(i), time.Now())
		if err := store.StoreBaseEntry(ctx, entry); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBadgerReads tests Badger read performance
func BenchmarkBadgerReads(b *testing.B) {
	tempDir := b.TempDir()
	store, err := NewStore(BackendBadger, tempDir, 0, 4096)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()

	// Pre-populate data
	entries := make([]*v1.BaseEntry, 1000)
	for i := 0; i < 1000; i++ {
		entry := createBenchEntry(uint64(i), time.Now())
		entries[i] = entry
		if err := store.StoreBaseEntry(ctx, entry); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := i % 1000
		if _, err := store.LoadBaseEntry(ctx, entries[idx].GetId()); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPebbleReads tests Pebble read performance
func BenchmarkPebbleReads(b *testing.B) {
	tempDir := b.TempDir()
	store, err := NewStore(BackendPebble, tempDir, 0, 4096)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()

	// Pre-populate data
	entries := make([]*v1.BaseEntry, 1000)
	for i := 0; i < 1000; i++ {
		entry := createBenchEntry(uint64(i), time.Now())
		entries[i] = entry
		if err := store.StoreBaseEntry(ctx, entry); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := i % 1000
		if _, err := store.LoadBaseEntry(ctx, entries[idx].GetId()); err != nil {
			b.Fatal(err)
		}
	}
}

// TestMemoryGrowth tests memory growth characteristics
func TestMemoryGrowthComparison(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory growth test in short mode")
	}

	backends := []BackendType{BackendBadger, BackendPebble}
	results := make(map[BackendType][]MemoryStats)

	for _, backend := range backends {
		t.Run(string(backend), func(t *testing.T) {
			tempDir := t.TempDir()
			store, err := NewStore(backend, tempDir, 0, 4096)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()

			ctx := context.Background()
			stats := []MemoryStats{}

			// Initial measurement
			stats = append(stats, getMemoryStats())

			// Write data in batches and measure memory
			batchSizes := []int{100, 500, 1000, 5000, 10000}
			totalEntries := 0

			for _, batchSize := range batchSizes {
				for i := 0; i < batchSize; i++ {
					entry := createBenchEntry(uint64(totalEntries+i+1), time.Now())
					if err := store.StoreBaseEntry(ctx, entry); err != nil {
						t.Fatal(err)
					}

					// Add some payload data
					payload := make([]byte, 1024) // 1KB payload
					for j := range payload {
						payload[j] = byte(i % 256)
					}
					if err := store.AddPayload(ctx, entry.GetId(), 0, payload); err != nil {
						t.Fatal(err)
					}
				}
				totalEntries += batchSize

				// Measure memory after each batch
				stat := getMemoryStats()
				stats = append(stats, stat)

				t.Logf("%s - After %d entries: Alloc=%d MB, Sys=%d MB, NumGC=%d",
					backend,
					totalEntries,
					stat.Alloc/1024/1024,
					stat.Sys/1024/1024,
					stat.NumGC)
			}

			results[backend] = stats
		})
	}

	// Compare final memory usage
	t.Log("\n=== Memory Growth Comparison ===")
	for _, backend := range backends {
		stats := results[backend]
		initial := stats[0]
		final := stats[len(stats)-1]

		allocGrowth := float64(final.Alloc-initial.Alloc) / float64(initial.Alloc) * 100
		sysGrowth := float64(final.Sys-initial.Sys) / float64(initial.Sys) * 100

		t.Logf("\n%s Backend:", backend)
		t.Logf("  Initial Alloc: %d MB", initial.Alloc/1024/1024)
		t.Logf("  Final Alloc:   %d MB", final.Alloc/1024/1024)
		t.Logf("  Alloc Growth:  %.2f%%", allocGrowth)
		t.Logf("  Initial Sys:   %d MB", initial.Sys/1024/1024)
		t.Logf("  Final Sys:     %d MB", final.Sys/1024/1024)
		t.Logf("  Sys Growth:    %.2f%%", sysGrowth)
		t.Logf("  GC Count:      %d", final.NumGC-initial.NumGC)
	}
}
