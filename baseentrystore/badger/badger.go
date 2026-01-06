package badger

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/options"
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

// badgerZerolog adapts zerolog to badger.Logger
type badgerZerolog struct{}

func (badgerZerolog) Errorf(format string, args ...interface{})   { log.Error().Msgf(format, args...) }
func (badgerZerolog) Warningf(format string, args ...interface{}) { log.Warn().Msgf(format, args...) }
func (badgerZerolog) Infof(format string, args ...interface{})    { log.Debug().Msgf(format, args...) } // Internal lib has some spammy info logs
func (badgerZerolog) Debugf(format string, args ...interface{})   { log.Debug().Msgf(format, args...) }

// baseEntryStore implements BaseEntryStore using BadgerDB directly
type baseEntryStore struct {
	db               *customDB
	maxDbSize        int64
	payloadChunkSize uint32
	cleanupInterval  time.Duration
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	cleanupMutex     sync.Mutex
}

// Config holds configuration options for BadgerDB
type Config struct {
	Dir                     string
	ValueDir                string
	SyncWrites              bool
	NumVersionsToKeep       int
	CompactL0OnClose        bool
	LevelSizeMultiplier     int
	MaxLevels               int
	ValueThreshold          int64
	NumMemtables            int
	BlockSize               int
	BloomFalsePositive      float64
	IndexCacheSize          int64
	NumLevelZeroTables      int
	NumLevelZeroTablesStall int
	MemTableSize            int64
	ValueLogFileSize        int64
	TTL                     time.Duration
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig(dir string) *Config {
	return &Config{
		Dir:                     dir,
		ValueDir:                "", // Same as Dir
		SyncWrites:              false,
		NumVersionsToKeep:       1,
		CompactL0OnClose:        true,
		LevelSizeMultiplier:     10,
		MaxLevels:               7,
		ValueThreshold:          1024,
		NumMemtables:            5,
		BlockSize:               4 * 1024,
		BloomFalsePositive:      0.01,
		IndexCacheSize:          0, // Use default
		NumLevelZeroTables:      5,
		NumLevelZeroTablesStall: 15,
		MemTableSize:            64 << 20, // 64MB
		ValueLogFileSize:        64 << 20, // 64MB
		TTL:                     0,        // No expiration by default
	}
}

// toBadgerOptions converts Config to badger.Options
func (c *Config) toBadgerOptions() badger.Options {
	opts := badger.DefaultOptions(c.Dir)
	if c.ValueDir != "" {
		opts = opts.WithValueDir(c.ValueDir)
	}
	opts = opts.
		WithLogger(badgerZerolog{}).
		WithSyncWrites(c.SyncWrites).
		WithNumVersionsToKeep(c.NumVersionsToKeep).
		WithCompactL0OnClose(c.CompactL0OnClose).
		WithLevelSizeMultiplier(c.LevelSizeMultiplier).
		WithMaxLevels(c.MaxLevels).
		WithValueThreshold(c.ValueThreshold).
		WithNumMemtables(c.NumMemtables).
		WithBlockSize(c.BlockSize).
		WithBloomFalsePositive(c.BloomFalsePositive).
		WithNumLevelZeroTables(c.NumLevelZeroTables).
		WithNumLevelZeroTablesStall(c.NumLevelZeroTablesStall).
		WithMemTableSize(c.MemTableSize).
		WithValueLogFileSize(c.ValueLogFileSize)
	if c.IndexCacheSize > 0 {
		opts = opts.WithIndexCacheSize(c.IndexCacheSize)
	}
	return opts
}

// NewBadgerStore creates a new BaseEntryStore with direct BadgerDB implementation
func NewBadgerStore(name string, maxDbSize int64, payloadChunkSize uint32, cleanupInterval time.Duration) (*baseEntryStore, error) {
	if maxDbSize < 0 {
		maxDbSize = 0
	}
	if cleanupInterval == 0 {
		cleanupInterval = 1 * time.Minute // Default to 1 minute
	}
	config := DefaultConfig(name)
	config.SyncWrites = false
	config.NumVersionsToKeep = 1
	// As soon as payloads are organized to be separated by chunk,
	// we can use the chunk size as the value threshold
	config.ValueThreshold = int64(payloadChunkSize)
	// config.ValueLogFileSize = lowerPowerOf2(maxDbSize / 4)
	config.ValueLogFileSize = 32 << 20 // 32 MB - larger files reduce compaction overhead
	config.MemTableSize = 64 << 20     // 64 MB - match Pebble config, reduce L0 flush frequency
	config.NumMemtables = 8            // Increased from 5 for better write concurrency
	config.CompactL0OnClose = true

	opts := config.toBadgerOptions()
	// opts = opts.WithValueThreshold(0)         // XXX
	opts = opts.WithIndexCacheSize(128 << 20) // 128 MB - increased for better index lookup performance
	opts = opts.WithCompression(options.None) // Disable compression for faster writes
	opts = opts.WithBlockCacheSize(0)         // XXX - explicit control of caching

	db, err := NewCustomDB(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create badger db: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &baseEntryStore{
		db:               db,
		maxDbSize:        maxDbSize,
		payloadChunkSize: payloadChunkSize,
		cleanupInterval:  cleanupInterval,
		ctx:              ctx,
		cancel:           cancel,
	}

	// Start background cleanup worker if cleanup is enabled
	if maxDbSize > 0 {
		s.startCleanupWorker()
	}

	return s, nil
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

// StoreBaseEntry stores the base entry and creates only cleanup time index
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
	// entryTime := entry.GetTimestamp().AsTime()
	err = s.update(func(txn *customTxn) error {
		// Store base entry
		if err := txn.Set(entryKey(entryId), entryData); err != nil {
			return fmt.Errorf("failed to store base entry: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to store base entry: %w", err)
	}
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
			payload = payload[writeLen:]
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to write payload chunks atomically: %w", err)
	}

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
			pcap = pcap[writeLen:]
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to write pcap chunks atomically: %w", err)
	}
	return nil
}

// LoadBaseEntry loads the base entry from the store
func (s *baseEntryStore) LoadBaseEntry(ctx context.Context, entryId uint64) (*v1.BaseEntry, error) {
	var entryData []byte
	err := s.view(func(txn *customTxn) error {
		item, err := txn.Get(entryKey(entryId))
		if err != nil {
			return err
		}
		entryData, err = item.ValueCopy(nil)
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
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(startKey); it.ValidForPrefix(prefix); it.Next() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Early termination if we've read enough
			if currentOffset >= targetEnd {
				break
			}

			key := it.Item().Key()
			chunkId, err := parseFixedWidthU32AtEnd(key)
			if err != nil {
				log.Error().Err(err).Str("key", string(key)).Msg("failed to parse chunk ID")
				return err
			}

			chunkData, err := it.Item().ValueCopy(nil)
			if err != nil {
				return fmt.Errorf("failed to read chunk %d: %w", chunkId, err)
			}

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
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load payload: %w", err)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("payload not found for id: %v", entryId)
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
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(startKey); it.ValidForPrefix(prefix); it.Next() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if currentOffset >= targetEnd {
				break
			}

			key := it.Item().Key()
			chunkId, err := parseFixedWidthU32AtEnd(key)
			if err != nil {
				log.Error().Err(err).Str("key", string(key)).Msg("Failed to parse chunk ID")
				return err
			}

			chunkData, err := it.Item().ValueCopy(nil)
			if err != nil {
				return fmt.Errorf("failed to read pcap chunk %d: %w", chunkId, err)
			}

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
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load pcap: %w", err)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("pcap not found")
	}
	return result, nil
}

// GetCurrentSize returns the current database size
func (s *baseEntryStore) GetCurrentSize() (lsmSize, vlogSize, realSize int64) {
	lsmSize, vlogSize = s.db.Size()
	// realSize = s.db.GetSize()
	realSize = lsmSize + vlogSize
	return lsmSize, vlogSize, realSize
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
		opts := badger.DefaultIteratorOptions
		opts.Reverse = true
		opts.Prefix = prefix

		it := txn.NewIterator(opts)
		defer it.Close()

		// Seek just past the prefix; reverse iterator puts us at the last key in the prefix.
		seekKey := append(append([]byte(nil), prefix...), 0xFF)
		it.Seek(seekKey)

		if it.ValidForPrefix(prefix) {
			key := it.Item().Key()
			cid, err := parseFixedWidthU32AtEnd(key)
			if err != nil {
				log.Error().Err(err).Str("key", string(key)).Msg("invalid payload key")
				return err
			}
			lastChunkId = cid

			if err := it.Item().Value(func(val []byte) error {
				// If the last chunk is exactly full, the next chunk id is the append target.
				if len(val) == int(s.payloadChunkSize) {
					lastChunkId++
					return nil
				}
				lastChunkData = append([]byte(nil), val...)
				return nil
			}); err != nil {
				return fmt.Errorf("failed to read last chunk data: %w", err)
			}
		}
		return nil
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
		opts := badger.DefaultIteratorOptions
		opts.Reverse = true
		opts.Prefix = prefix

		it := txn.NewIterator(opts)
		defer it.Close()

		seekKey := append(append([]byte(nil), prefix...), 0xFF)
		it.Seek(seekKey)

		if it.ValidForPrefix(prefix) {
			key := it.Item().Key()
			cid, err := parseFixedWidthU32AtEnd(key)
			if err != nil {
				log.Error().Err(err).Str("key", string(key)).Msg("malformed pcap key")
				return err
			}
			lastChunkId = cid

			if err := it.Item().Value(func(val []byte) error {
				if len(val) == int(s.payloadChunkSize) {
					lastChunkId++
					return nil
				}
				lastChunkData = append([]byte(nil), val...)
				return nil
			}); err != nil {
				return fmt.Errorf("failed to read last pcap chunk data: %w", err)
			}
		}
		return nil
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

// startCleanupWorker starts a background goroutine that performs periodic cleanup
func (s *baseEntryStore) startCleanupWorker() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		ticker := time.NewTicker(s.cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.performBackgroundCleanup()
			case <-s.ctx.Done():
				return
			}
		}
	}()
}

// cleanupResult holds statistics from a cleanup operation
type cleanupResult struct {
	count int   // number of entries removed
	bytes int64 // total bytes removed
}

// performBackgroundCleanup checks if cleanup is needed and removes entries to bring DB size within limit
func (s *baseEntryStore) performBackgroundCleanup() {
	if s.maxDbSize == 0 {
		return
	}

	// Try to acquire lock, skip if already running
	if !s.cleanupMutex.TryLock() {
		log.Debug().Msg("Cleanup already in progress, skipping")
		return
	}
	defer s.cleanupMutex.Unlock()

	lsmSize, vlogSize, realSize := s.GetCurrentSize()
	if realSize <= s.maxDbSize {
		log.Info().Int64("lsmSize", lsmSize).Int64("vlogSize", vlogSize).Int64("realSize", realSize).Int64("maxDbSize", s.maxDbSize).Msg("DB size within limit, no cleanup needed")
		return
	}

	bytesToRemove := realSize - s.maxDbSize

	log.Info().Int64("lsmSize", lsmSize).Int64("vlogSize", vlogSize).Int64("realSize", realSize).Int64("maxDbSize", s.maxDbSize).Int64("bytesToRemove", bytesToRemove).Msg("Starting background cleanup")

	result := s.removeEntriesByBytes(bytesToRemove)

	log.Info().Int("entriesRemoved", result.count).Int64("bytesRemoved", result.bytes).Msg("Background cleanup completed")

	// Run value log GC if needed
	if err := s.db.DB.RunValueLogGC(0.5); err != nil && err != badger.ErrNoRewrite {
		log.Error().Err(err).Msg("Failed to run vlog GC")
	}
}

// removeEntriesByBytes removes oldest entries until at least targetBytes have been removed
func (s *baseEntryStore) removeEntriesByBytes(targetBytes int64) cleanupResult {
	result := cleanupResult{}

	err := s.update(func(txn *customTxn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte("e:")
		it := txn.NewIterator(opts)
		defer it.Close()

		counter := 0
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.KeyCopy(nil)

			// Only process base entry keys (length 22: "e:" + 20 digits)
			if len(key) != 22 {
				counter++
			}
			result.count++
			result.bytes += int64(len(key)) + item.ValueSize()
			if err := txn.Delete(key); err != nil {
				return fmt.Errorf("failed to delete key %s: %w", string(key), err)
			}
			// Check if we've removed enough
			if result.bytes >= targetBytes {
				break
			}
		}

		return nil
	})
	if err != nil {
		log.Error().Err(err).Msg("Cleanup transaction failed")
		return result
	}
	log.Info().Int("entriesRemoved", result.count).Int64("bytesRemoved", result.bytes).Msg("Transaction passed") // XXX

	return result
}

// ListEntries returns all entry IDs
func (s *baseEntryStore) ListEntries(ctx context.Context) ([]uint64, error) {
	var entryIds []uint64
	err := s.view(func(txn *customTxn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte("e:")
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.ValidForPrefix(opts.Prefix); it.Next() {
			if len(it.Item().Key()) != 22 {
				// TODO: validate instead of 22
				continue
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			key := it.Item().Key()
			if len(key) > 2 {
				entryIdStr := string(key[2:])
				id, err := strconv.ParseUint(entryIdStr, 10, 64)
				if err != nil {
					log.Error().Err(err).Msgf("Failed to decode entry ID from key %s", key)
					continue
				}
				entryIds = append(entryIds, id)
			}
		}
		return nil
	})
	return entryIds, err
}

// lowerPowerOf2 returns the highest power of 2 that is less than or equal to n
// BadgerDB requires ValueLogFileSize to be in the range [1MB, 2GB)
func lowerPowerOf2(n int64) int64 {
	const minSize = 1 << 20   // 1MB
	const maxSize = 2<<30 - 1 // 2GB - 1byte
	if n < 0 {
		return 0
	}
	if n == 0 {
		return maxSize
	}
	power := int64(1)
	for power <= n/2 {
		power *= 2
	}
	if power < minSize {
		return minSize
	}
	if power > maxSize {
		return maxSize / 2
	}
	return power
}
