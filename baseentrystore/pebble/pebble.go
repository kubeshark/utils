package pebble

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/bloom"
	v1 "github.com/kubeshark/api2/pkg/proto/capture/v1"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/gopacket/pcapgo"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/proto"
)

// emptyPcapHeader is a pre-calculated PCAP file header with LinkTypeRaw (IP packets)
// Used when no pcap chunks exist for an entry to ensure a valid PCAP file structure.
var emptyPcapHeader = func() []byte {
	buf := new(bytes.Buffer)
	w := pcapgo.NewWriter(buf)
	if err := w.WriteFileHeader(65535, layers.LinkTypeRaw); err != nil {
		panic(fmt.Sprintf("failed to create empty pcap header: %v", err))
	}
	return buf.Bytes()
}()

// baseEntryStore implements BaseEntryStore using Pebble
type baseEntryStore struct {
	db               *customDB
	maxDbSize        int64
	payloadChunkSize uint32
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	flushMutex       sync.Mutex
	cleanupInterval  time.Duration
	syncInterval     time.Duration // Interval for periodic WAL sync (default 1 second)
	// Internal counters for tracking stored data
	storedBytes  int64
	storedKeys   int64
	counterMutex sync.RWMutex
}

// pebbleLogger adapts zerolog to pebble.Logger
type pebbleLogger struct{}

func (pebbleLogger) Infof(format string, args ...interface{})  { log.Info().Msgf(format, args...) }
func (pebbleLogger) Errorf(format string, args ...interface{}) { log.Error().Msgf(format, args...) }
func (pebbleLogger) Fatalf(format string, args ...interface{}) { log.Fatal().Msgf(format, args...) }

// NewPebbleStore creates a new BaseEntryStore with Pebble implementation
func NewPebbleStore(name string, maxDbSize int64, payloadChunkSize uint32, cleanupInterval time.Duration) (*baseEntryStore, error) {
	if maxDbSize < 0 {
		maxDbSize = 0
	}

	opts := &pebble.Options{
		Cache:                       pebble.NewCache(128 << 20), // 128 MiB cache (user constraint)
		MemTableSize:                64 << 20,                   // 64 MiB memtables (fewer L0 flushes)
		MemTableStopWritesThreshold: 6,                          // Max 6 memtables = 384 MiB
		L0CompactionThreshold:       6,                          // Relaxed threshold for better write throughput
		L0StopWritesThreshold:       12,                         // Wider margin before blocking writes
		LBaseMaxBytes:               1 << 30,                    // 1 GiB
		WALBytesPerSync:             4 << 20,                    // 4 MiB - reduce fsync frequency for WAL
		BytesPerSync:                4 << 20,                    // 4 MiB - reduce fsync frequency during compaction
		Logger:                      pebbleLogger{},
		MaxConcurrentCompactions:    func() int { return 2 }, // Parallel compactions to keep up with writes

		Levels: []pebble.LevelOptions{
			{
				TargetFileSize: 32 << 20,
				BlockSize:      32 << 10,
				IndexBlockSize: 8 << 10,
				FilterPolicy:   bloom.FilterPolicy(10), // Bloom filter with 10 bits per key (~1% false positive rate)
				Compression:    pebble.DefaultCompression,
			},
			{
				TargetFileSize: 64 << 20,
				BlockSize:      32 << 10,
				IndexBlockSize: 8 << 10,
				FilterPolicy:   bloom.FilterPolicy(10), // Bloom filter with 10 bits per key (~1% false positive rate)
				Compression:    pebble.DefaultCompression,
			},
		},
	}

	db, err := NewCustomDB(opts, name)
	if err != nil {
		return nil, fmt.Errorf("failed to create pebble db: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &baseEntryStore{
		db:               db,
		maxDbSize:        maxDbSize,
		payloadChunkSize: payloadChunkSize,
		ctx:              ctx,
		cancel:           cancel,
		cleanupInterval:  cleanupInterval,
		syncInterval:     1 * time.Second, // Periodic sync to ensure durability (max 1s data loss)
	}

	// Initialize counters by iterating through all existing keys
	if err := s.initializeCounters(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize counters: %w", err)
	}

	// Start periodic sync worker to ensure WAL is fsynced every second
	s.startSyncWorker()

	if maxDbSize > 0 {
		s.startCleanupWorker()
	}

	return s, nil
}

// initializeCounters scans the database to initialize storedBytes and storedKeys
func (s *baseEntryStore) initializeCounters() error {
	var totalBytes int64
	var totalKeys int64

	err := s.view(func(txn *customTxn) error {
		prefix := []byte("e:")
		iter := txn.NewIter(&pebble.IterOptions{
			LowerBound: prefix,
			UpperBound: append(prefix, 0xFF),
			KeyTypes:   pebble.IterKeyTypePointsOnly,
		})
		defer iter.Close()

		for iter.SeekGE(prefix); iter.Valid(); iter.Next() {
			key := iter.Key()
			if !bytes.HasPrefix(key, prefix) {
				break
			}
			value := iter.Value()
			totalBytes += int64(len(key) + len(value))
			totalKeys++
		}
		return iter.Error()
	})
	if err != nil {
		return err
	}

	s.counterMutex.Lock()
	s.storedBytes = totalBytes
	s.storedKeys = totalKeys
	s.counterMutex.Unlock()

	log.Info().
		Int64("storedBytes", totalBytes).
		Int64("storedKeys", totalKeys).
		Msg("Initialized counters")

	return nil
}

// Key generation functions
const chunkWidth = 10

func entryKey(entryId uint64) []byte {
	return []byte(fmt.Sprintf("e:%020d", entryId))
}

func payloadChunkKey(entryId uint64, payloadId uint32, chunkId uint32) []byte {
	return []byte(fmt.Sprintf(
		"e:%020d:pd:%0*d:%0*d",
		entryId,
		chunkWidth, payloadId,
		chunkWidth, chunkId,
	))
}

func pcapChunkKey(entryId uint64, chunkId uint32) []byte {
	return []byte(fmt.Sprintf(
		"e:%020d:pc:%0*d",
		entryId,
		chunkWidth, chunkId,
	))
}

// parseFixedWidthU32AtEnd reads the last fixed-width decimal segment after ':'
func parseFixedWidthU32AtEnd(key []byte) (uint32, error) {
	i := bytes.LastIndexByte(key, ':')
	if i < 0 || i+1+chunkWidth > len(key) {
		return 0, fmt.Errorf("malformed key: %q", string(key))
	}
	v, err := strconv.ParseUint(string(key[i+1:i+1+chunkWidth]), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse chunk id: %w", err)
	}
	return uint32(v), nil
}

// StoreBaseEntry stores the base entry
func (s *baseEntryStore) StoreBaseEntry(ctx context.Context, entry *v1.BaseEntry) error {
	entryId := entry.GetId()
	if entryId == 0 {
		return fmt.Errorf("entry ID cannot be empty")
	}

	// Serialize the protobuf BaseEntry
	entryData, err := proto.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal base entry: %w", err)
	}
	if entry.GetTimestamp().Seconds == 0 {
		log.Fatal().Uint64("entryId", entryId).Msg("Timestamp is zero")
		return nil
	}

	key := entryKey(entryId)
	err = s.update(func(txn *customTxn) error {
		// Store base entry
		if err := txn.Set(key, entryData); err != nil {
			return fmt.Errorf("failed to store base entry: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to store base entry: %w", err)
	}

	// Update counters
	s.counterMutex.Lock()
	s.storedKeys++
	s.storedBytes += int64(len(key) + len(entryData))
	s.counterMutex.Unlock()

	// s.performCleanup()
	return nil
}

// AddPayload appends payload data using chunking logic
func (s *baseEntryStore) AddPayload(ctx context.Context, entryId uint64, payloadId uint32, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}

	// Find the last chunk to append to
	lastChunkId, lastChunkData, err := s.findLastPayloadChunk(ctx, entryId, payloadId)
	if err != nil {
		return fmt.Errorf("failed to find last chunk: %w", err)
	}

	var bytesAdded int64
	var keysAdded int64

	err = s.update(func(txn *customTxn) error {
		payloadLen := len(payload)
		chunkSize := int(s.payloadChunkSize)

		// Write to the last chunk if it has space
		if len(lastChunkData) < chunkSize && payloadLen > 0 {
			space := chunkSize - len(lastChunkData)
			if space > payloadLen {
				space = payloadLen
			}
			chunkData := append(append([]byte(nil), lastChunkData...), payload[:space]...)
			key := payloadChunkKey(entryId, payloadId, lastChunkId)
			if err := txn.Set(key, chunkData); err != nil {
				return fmt.Errorf("failed to write chunk: %w", err)
			}
			// Updated existing chunk: delta is the size difference
			bytesAdded += int64(len(chunkData) - len(lastChunkData))
			payload = payload[space:]
		}

		// Write new chunks for the rest
		for i := 0; len(payload) > 0; i++ {
			writeLen := chunkSize
			if writeLen > len(payload) {
				writeLen = len(payload)
			}
			key := payloadChunkKey(entryId, payloadId, lastChunkId+1+uint32(i))
			if err := txn.Set(key, payload[:writeLen]); err != nil {
				return fmt.Errorf("failed to write chunk: %w", err)
			}
			// New chunk: add full size
			bytesAdded += int64(len(key) + writeLen)
			keysAdded++
			payload = payload[writeLen:]
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to write payload chunks atomically: %w", err)
	}

	// Update counters
	s.counterMutex.Lock()
	s.storedBytes += bytesAdded
	s.storedKeys += keysAdded
	s.counterMutex.Unlock()

	// s.performCleanup()
	return nil
}

// AddPcap appends pcap data using chunking logic
func (s *baseEntryStore) AddPcap(ctx context.Context, entryId uint64, pcap []byte) error {
	if len(pcap) == 0 {
		return nil
	}

	// Find the last chunk to append to
	lastChunkId, lastChunkData, err := s.findLastPcapChunk(ctx, entryId)
	if err != nil {
		return fmt.Errorf("failed to find last pcap chunk: %w", err)
	}

	var bytesAdded int64
	var keysAdded int64

	err = s.update(func(txn *customTxn) error {
		pcapLen := len(pcap)
		chunkSize := int(s.payloadChunkSize)

		// Write to the last chunk if it has space
		if len(lastChunkData) < chunkSize && pcapLen > 0 {
			space := chunkSize - len(lastChunkData)
			if space > pcapLen {
				space = pcapLen
			}
			chunkData := append(append([]byte(nil), lastChunkData...), pcap[:space]...)
			key := pcapChunkKey(entryId, lastChunkId)
			if err := txn.Set(key, chunkData); err != nil {
				return fmt.Errorf("failed to write pcap chunk: %w", err)
			}
			// Updated existing chunk: delta is the size difference
			bytesAdded += int64(len(chunkData) - len(lastChunkData))
			pcap = pcap[space:]
		}

		// Write new chunks for the rest
		for i := 0; len(pcap) > 0; i++ {
			writeLen := chunkSize
			if writeLen > len(pcap) {
				writeLen = len(pcap)
			}
			key := pcapChunkKey(entryId, lastChunkId+1+uint32(i))
			if err := txn.Set(key, pcap[:writeLen]); err != nil {
				return fmt.Errorf("failed to write pcap chunk: %w", err)
			}
			// New chunk: add full size
			bytesAdded += int64(len(key) + writeLen)
			keysAdded++
			pcap = pcap[writeLen:]
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to write pcap chunks atomically: %w", err)
	}

	// Update counters
	s.counterMutex.Lock()
	s.storedBytes += bytesAdded
	s.storedKeys += keysAdded
	s.counterMutex.Unlock()

	// s.performCleanup()
	return nil
}

// LoadBaseEntry loads the base entry from the store
func (s *baseEntryStore) LoadBaseEntry(ctx context.Context, entryId uint64) (*v1.BaseEntry, error) {
	var entryData []byte
	err := s.view(func(txn *customTxn) error {
		var err error
		entryData, err = txn.Get(entryKey(entryId))
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read base entry: %w", err)
	}
	var entry v1.BaseEntry
	if err := proto.Unmarshal(entryData, &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal base entry: %w", err)
	}
	return &entry, nil
}

// LoadPayload loads a payload with offset and length support
func (s *baseEntryStore) LoadPayload(ctx context.Context, entryId uint64, payloadId uint32, offset uint64, length int64) ([]byte, error) {
	startChunkId := offset / uint64(s.payloadChunkSize)
	startKey := payloadChunkKey(entryId, payloadId, uint32(startChunkId))

	var result []byte
	var currentOffset uint64 = startChunkId * uint64(s.payloadChunkSize)
	var targetEnd uint64
	if length == -1 {
		targetEnd = ^uint64(0)
	} else {
		targetEnd = offset + uint64(length)
	}

	prefix := []byte(fmt.Sprintf("e:%020d:pd:%0*d:", entryId, chunkWidth, payloadId))
	err := s.view(func(txn *customTxn) error {
		iter := txn.NewIter(&pebble.IterOptions{
			LowerBound: startKey,
			UpperBound: append(prefix, 0xFF), // Exclusive upper bound
			KeyTypes:   pebble.IterKeyTypePointsOnly,
		})
		defer iter.Close()

		for iter.SeekGE(startKey); iter.Valid(); iter.Next() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			key := iter.Key()
			if !bytes.HasPrefix(key, prefix) {
				break
			}

			// Early termination if we've read enough
			if currentOffset >= targetEnd {
				break
			}

			chunkId, err := parseFixedWidthU32AtEnd(key)
			if err != nil {
				log.Error().Err(err).Str("key", string(key)).Msg("failed to parse chunk ID")
				return err
			}

			chunkData := make([]byte, len(iter.Value()))
			copy(chunkData, iter.Value())

			// Calculate chunk boundaries
			chunkStart := uint64(chunkId) * uint64(s.payloadChunkSize)
			chunkEnd := chunkStart + uint64(len(chunkData))

			// Skip if this chunk doesn't overlap with target range
			if chunkStart >= targetEnd {
				currentOffset = chunkEnd
				break
			}

			// Calculate slice boundaries within this chunk
			sliceStart := uint64(0)
			if offset > chunkStart {
				sliceStart = offset - chunkStart
			}
			sliceEnd := uint64(len(chunkData))
			if chunkStart+sliceEnd > targetEnd {
				sliceEnd = targetEnd - chunkStart
			}

			// Bounds check and append
			if sliceStart < uint64(len(chunkData)) && sliceEnd <= uint64(len(chunkData)) && sliceStart < sliceEnd {
				result = append(result, chunkData[sliceStart:sliceEnd]...)
			}
			currentOffset = chunkEnd
		}
		return iter.Error()
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load payload: %w", err)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("payload not found")
	}
	return result, nil
}

// LoadPcap loads PCAP data with offset and length support
func (s *baseEntryStore) LoadPcap(ctx context.Context, entryId uint64, offset uint64, length int64) ([]byte, error) {
	startChunkId := offset / uint64(s.payloadChunkSize)
	startKey := pcapChunkKey(entryId, uint32(startChunkId))

	var result []byte
	var currentOffset uint64 = startChunkId * uint64(s.payloadChunkSize)
	var targetEnd uint64
	if length == -1 {
		targetEnd = ^uint64(0)
	} else {
		targetEnd = offset + uint64(length)
	}

	prefix := []byte(fmt.Sprintf("e:%020d:pc:", entryId))
	err := s.view(func(txn *customTxn) error {
		iter := txn.NewIter(&pebble.IterOptions{
			LowerBound: startKey,
			UpperBound: append(prefix, 0xFF),
			KeyTypes:   pebble.IterKeyTypePointsOnly,
		})
		defer iter.Close()

		for iter.SeekGE(startKey); iter.Valid(); iter.Next() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			key := iter.Key()
			if !bytes.HasPrefix(key, prefix) {
				break
			}

			if currentOffset >= targetEnd {
				break
			}

			chunkId, err := parseFixedWidthU32AtEnd(key)
			if err != nil {
				log.Error().Err(err).Str("key", string(key)).Msg("Failed to parse chunk ID")
				return err
			}

			chunkData := make([]byte, len(iter.Value()))
			copy(chunkData, iter.Value())

			chunkStart := uint64(chunkId) * uint64(s.payloadChunkSize)
			chunkEnd := chunkStart + uint64(len(chunkData))
			if chunkStart >= targetEnd {
				currentOffset = chunkEnd
				break
			}

			sliceStart := uint64(0)
			if offset > chunkStart {
				sliceStart = offset - chunkStart
			}
			sliceEnd := uint64(len(chunkData))
			if chunkStart+sliceEnd > targetEnd {
				sliceEnd = targetEnd - chunkStart
			}
			if sliceStart < uint64(len(chunkData)) && sliceEnd <= uint64(len(chunkData)) && sliceStart < sliceEnd {
				result = append(result, chunkData[sliceStart:sliceEnd]...)
			}
			currentOffset = chunkEnd
		}
		return iter.Error()
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load pcap: %w", err)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("pcap not found")
	}
	return result, nil
}

// GetCurrentSize returns the current database size from internal counters
func (s *baseEntryStore) GetCurrentSize() (lsmSize, vlogSize, realSize int64) {
	s.counterMutex.RLock()
	defer s.counterMutex.RUnlock()
	realSize = s.storedBytes
	return lsmSize, vlogSize, realSize
}

// humanReadableSize converts bytes to human-readable format
func humanReadableSize(b uint64) string {
	const (
		KiB = 1 << 10
		MiB = 1 << 20
		GiB = 1 << 30
		TiB = 1 << 40
	)
	switch {
	case b >= TiB:
		return fmt.Sprintf("%.2f TiB", float64(b)/TiB)
	case b >= GiB:
		return fmt.Sprintf("%.2f GiB", float64(b)/GiB)
	case b >= MiB:
		return fmt.Sprintf("%.2f MiB", float64(b)/MiB)
	case b >= KiB:
		return fmt.Sprintf("%.2f KiB", float64(b)/KiB)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// humanSizeDiff returns a human-readable size difference
func humanSizeDiff(a, b uint64) string {
	if b > a {
		return "+" + humanReadableSize(b-a)
	}
	return "-" + humanReadableSize(a-b)
}

// Close closes the store and stops background cleanup
func (s *baseEntryStore) Close() error {
	s.cancel()
	s.wg.Wait()
	return s.db.Close()
}

// Helper methods for finding last chunks
func (s *baseEntryStore) findLastPayloadChunk(ctx context.Context, entryId uint64, payloadId uint32) (uint32, []byte, error) {
	prefix := []byte(fmt.Sprintf("e:%020d:pd:%0*d:", entryId, chunkWidth, payloadId))

	var lastChunkId uint32
	var lastChunkData []byte

	err := s.view(func(txn *customTxn) error {
		iter := txn.NewIter(&pebble.IterOptions{
			LowerBound: prefix,
			UpperBound: append(prefix, 0xFF),
			KeyTypes:   pebble.IterKeyTypePointsOnly,
		})
		defer iter.Close()

		// Seek to last key with prefix
		if iter.SeekLT(append(prefix, 0xFF)); iter.Valid() && bytes.HasPrefix(iter.Key(), prefix) {
			key := iter.Key()
			cid, err := parseFixedWidthU32AtEnd(key)
			if err != nil {
				log.Error().Err(err).Str("key", string(key)).Msg("invalid payload key")
				return err
			}
			lastChunkId = cid

			val := iter.Value()
			// If the last chunk is exactly full, the next chunk id is the append target.
			if len(val) == int(s.payloadChunkSize) {
				lastChunkId++
			} else {
				lastChunkData = make([]byte, len(val))
				copy(lastChunkData, val)
			}
		}
		return iter.Error()
	})
	if err != nil {
		return 0, nil, err
	}
	return lastChunkId, lastChunkData, nil
}

func (s *baseEntryStore) findLastPcapChunk(ctx context.Context, entryId uint64) (uint32, []byte, error) {
	prefix := []byte(fmt.Sprintf("e:%020d:pc:", entryId))

	var lastChunkId uint32
	var lastChunkData []byte

	err := s.view(func(txn *customTxn) error {
		iter := txn.NewIter(&pebble.IterOptions{
			LowerBound: prefix,
			UpperBound: append(prefix, 0xFF),
			KeyTypes:   pebble.IterKeyTypePointsOnly,
		})
		defer iter.Close()

		if iter.SeekLT(append(prefix, 0xFF)); iter.Valid() && bytes.HasPrefix(iter.Key(), prefix) {
			key := iter.Key()
			cid, err := parseFixedWidthU32AtEnd(key)
			if err != nil {
				log.Error().Err(err).Str("key", string(key)).Msg("malformed pcap key")
				return err
			}
			lastChunkId = cid

			val := iter.Value()
			if len(val) == int(s.payloadChunkSize) {
				lastChunkId++
			} else {
				lastChunkData = make([]byte, len(val))
				copy(lastChunkData, val)
			}
		}
		return iter.Error()
	})
	if err != nil {
		return 0, nil, err
	}

	// If no pcap chunks exist, return a copy of the pre-calculated PCAP header with type IP
	if lastChunkId == 0 && lastChunkData == nil {
		header := make([]byte, len(emptyPcapHeader))
		copy(header, emptyPcapHeader)
		return 0, header, nil
	}

	return lastChunkId, lastChunkData, nil
}

// startSyncWorker starts a background worker that periodically syncs the WAL to disk
// This ensures durability with NoSync writes while limiting data loss to syncInterval duration
func (s *baseEntryStore) startSyncWorker() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		ticker := time.NewTicker(s.syncInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.flushMutex.Lock()

				// Force fsync of WAL by writing empty data with Sync option
				// This ensures all previously written data (with NoSync) is persisted to disk
				if err := s.db.LogData(nil, pebble.Sync); err != nil {
					log.Error().Err(err).Msg("Failed to sync WAL")
				}
				s.flushMutex.Unlock()
			case <-s.ctx.Done():
				s.flushMutex.Lock()
				// On shutdown, do a final sync to persist any pending writes
				if err := s.db.LogData(nil, pebble.Sync); err != nil {
					log.Error().Err(err).Msg("Failed to sync WAL on shutdown")
				}
				s.flushMutex.Unlock()
				return
			}
		}
	}()
}

func (s *baseEntryStore) startCleanupWorker() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		for {
			select {
			case <-s.ctx.Done():
				log.Info().Msg("pebble cleanup worker shutdown")
				return
			default:
			}

			s.performCleanup()

			time.Sleep(s.cleanupInterval)
		}
	}()
}

// performCleanup checks if cleanup is needed and removes entries to bring DB size within limit
func (s *baseEntryStore) performCleanup() {
	if s.maxDbSize == 0 {
		return
	}

	s.flushMutex.Lock()
	defer s.flushMutex.Unlock()

	_, _, sz := s.GetCurrentSize()
	size := uint64(sz)
	limit := uint64(s.maxDbSize)

	if size <= limit {
		log.Info().
			Str("size", humanReadableSize(size)).
			Str("limit", humanReadableSize(limit)).
			Msg("OK: live size ≤ limit")
		return
	}

	// Calculate bytes to remove
	over := size - limit

	log.Info().
		Str("size", humanReadableSize(size)).
		Str("limit", humanReadableSize(limit)).
		Int64("over", int64(over)).
		Msg("OVER: live size > limit; pruning toward limit")

	// Find and delete the span
	start, end, result := s.removeEntriesByBytes(int64(over))

	if start == nil || end == nil {
		log.Debug().Msg("Nothing to delete (empty DB)")
		return
	}

	// Recompute and report
	_, _, newSize := s.GetCurrentSize()
	log.Info().
		Str("oldSize", humanReadableSize(size)).
		Str("newSize", humanReadableSize(uint64(newSize))).
		Str("delta", humanSizeDiff(size, uint64(newSize))).
		Int64("bytesRemoved", result.bytes).
		Int("keysRemoved", result.count).
		Msg("AFTER: cleanup completed")
}

// cleanupResult holds statistics from a cleanup operation
type cleanupResult struct {
	count int   // number of keys removed
	bytes int64 // total bytes removed
}

// findSpanToDelete finds the key range [start, end) to delete by iterating from
// the oldest entries and accumulating approximate logical bytes (key+value) for ALL keys
// belonging to those entries (base entry + payload chunks + pcap chunks).
// Returns nil, nil, 0, 0 if there are no keys to delete.
func (s *baseEntryStore) findSpanToDelete(wantBytes uint64) (start, end []byte, bytesToDelete uint64, keysToDelete int) {
	var lastKey []byte
	err := s.view(func(txn *customTxn) error {
		prefix := []byte("e:")
		iter := txn.NewIter(&pebble.IterOptions{
			LowerBound: prefix,
			UpperBound: append(append([]byte(nil), prefix...), 0xFF),
			KeyTypes:   pebble.IterKeyTypePointsOnly,
		})
		defer iter.Close()

		for iter.First(); iter.Valid(); iter.Next() {
			key := iter.Key()
			if !bytes.HasPrefix(key, prefix) {
				break
			}
			if start == nil {
				start = bytes.Clone(key)
			}
			lastKey = bytes.Clone(key)
			value := iter.Value()
			bytesToDelete += uint64(len(key) + len(value))
			keysToDelete++
			if bytesToDelete >= wantBytes {
				break
			}
		}
		return iter.Error()
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to list entries for findSpanToDelete")
		return nil, nil, 0, 0
	}

	// Set end to just after the last key (exclusive upper bound for DeleteRange)
	if lastKey != nil {
		end = append(bytes.Clone(lastKey), 0x00)
	}

	return start, end, bytesToDelete, keysToDelete
}

// removeEntriesByBytes removes oldest entries until at least targetBytes have been removed
// using DeleteRange for efficient bulk deletion. Returns the start and end keys of the
// deleted range along with cleanup statistics.
func (s *baseEntryStore) removeEntriesByBytes(targetBytes int64) (start, end []byte, result cleanupResult) {
	// Find the span to delete
	start, end, bytesToDelete, keysToDelete := s.findSpanToDelete(uint64(targetBytes))

	if start == nil || end == nil || bytes.Compare(start, end) >= 0 {
		log.Warn().Str("start", printableKey(start)).Str("end", printableKey(end)).Msg("Nothing to delete (empty DB or insufficient data)")
		return nil, nil, cleanupResult{}
	}

	// We track logical bytes for accurate reporting
	result.bytes = int64(bytesToDelete)
	result.count = keysToDelete

	// Perform the range delete
	err := s.db.DeleteRange(start, end, pebble.NoSync)
	if err != nil {
		log.Error().Err(err).Msg("DeleteRange failed during cleanup")
		return start, end, cleanupResult{}
	}
	if err := s.db.Compact(start, end, true); err != nil {
		log.Error().Err(err).Msg("Compact failed during cleanup")
		return start, end, cleanupResult{}
	}

	// Update counters
	s.counterMutex.Lock()
	s.storedBytes -= int64(bytesToDelete)
	s.storedKeys -= int64(keysToDelete)
	s.counterMutex.Unlock()

	log.Info().
		Str("start", printableKey(start)).
		Str("end", printableKey(end)).
		Str("approxBytes", humanReadableSize(bytesToDelete)).
		Int("keysDeleted", keysToDelete).
		Msg("DeleteRange completed")

	return start, end, result
}

// printableKey converts a byte slice to a printable string for logging
func printableKey(b []byte) string {
	const max = 32
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b) && i < max; i++ {
		if b[i] >= 32 && b[i] < 127 {
			out = append(out, b[i])
		} else {
			out = append(out, '?')
		}
	}
	if len(b) > max {
		out = append(out, '.', '.', '.')
	}
	return string(out)
}

// ListEntries returns all entry IDs
func (s *baseEntryStore) ListEntries(ctx context.Context) ([]uint64, error) {
	var entryIds []uint64
	err := s.view(func(txn *customTxn) error {
		prefix := []byte("e:")
		iter := txn.NewIter(&pebble.IterOptions{
			LowerBound: prefix,
			UpperBound: append(prefix, 0xFF),
			KeyTypes:   pebble.IterKeyTypePointsOnly,
		})
		defer iter.Close()

		for iter.SeekGE(prefix); iter.Valid(); iter.Next() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			key := iter.Key()
			if !bytes.HasPrefix(key, prefix) {
				break
			}

			// Only parse base entry keys (e:{20-digit-id}), skip chunk keys
			if len(key) == 22 && bytes.HasPrefix(key, prefix) {
				entryIdStr := string(key[2:])
				id, err := strconv.ParseUint(entryIdStr, 10, 64)
				if err != nil {
					log.Error().Err(err).Msgf("Failed to decode entry ID from key %s", key)
					continue
				}
				entryIds = append(entryIds, id)
			}
		}
		return iter.Error()
	})
	return entryIds, err
}
