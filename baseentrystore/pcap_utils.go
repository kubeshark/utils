package baseentrystore

import (
	"encoding/binary"
	"time"
)

// CreatePcapPacketWithHeader creates a PCAP packet with a 16-byte packet header
// followed by the raw packet data. The packet header includes:
// - Timestamp seconds (4 bytes)
// - Timestamp microseconds (4 bytes)
// - Capture length (4 bytes)
// - Original length (4 bytes)
//
// This is used to ensure each packet/frame in the PCAP has proper headers.
func CreatePcapPacketWithHeader(timestamp time.Time, data []byte) []byte {
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	// Create 16-byte packet header
	var packetHeader [16]byte
	secs := timestamp.Unix()
	usecs := timestamp.Nanosecond() / 1000 // Convert nanoseconds to microseconds

	// Write packet header fields in little-endian format
	binary.LittleEndian.PutUint32(packetHeader[0:4], uint32(secs))        // Timestamp seconds
	binary.LittleEndian.PutUint32(packetHeader[4:8], uint32(usecs))       // Timestamp microseconds
	binary.LittleEndian.PutUint32(packetHeader[8:12], uint32(len(data)))  // Captured length
	binary.LittleEndian.PutUint32(packetHeader[12:16], uint32(len(data))) // Original length

	// Concatenate header + data
	result := make([]byte, 16+len(data))
	copy(result[0:16], packetHeader[:])
	copy(result[16:], data)

	return result
}
