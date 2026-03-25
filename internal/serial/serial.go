package serial

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	"micropki/internal/database"
	"micropki/internal/logger"
)

// GenerateUniqueSerial generates a 64-bit globally unique serial number.
// High 32 bits: Unix timestamp (seconds)
// Low 32 bits: CSPRNG value
// It checks against the database to ensure maximum safety against collisions,
// though the chance is astronomically low.
func GenerateUniqueSerial() (*big.Int, error) {
	for attempt := 0; attempt < 5; attempt++ { // Retry a few times in case of collision
		// High 32 bits
		now := uint32(time.Now().Unix())
		
		// Low 32 bits
		randBytes := make([]byte, 4)
		if _, err := rand.Read(randBytes); err != nil {
			return nil, fmt.Errorf("failed to read random bytes: %w", err)
		}
		randVal := binary.BigEndian.Uint32(randBytes)

		// Combine into 64-bit
		var combined [8]byte
		binary.BigEndian.PutUint32(combined[0:4], now)
		binary.BigEndian.PutUint32(combined[4:8], randVal)

		serial := new(big.Int).SetBytes(combined[:])
		serialHex := fmt.Sprintf("%x", serial)

		// If DB is initialized, check for collision
		if database.DB != nil {
			exists, err := database.CheckSerialExists(serialHex)
			if err != nil {
				return nil, fmt.Errorf("failed to check serial existence: %w", err)
			}
			if exists {
				logger.Warning("Serial %s already exists, retrying", serialHex)
				continue
			}
		}

		return serial, nil
	}

	return nil, fmt.Errorf("failed to generate unique serial after 5 attempts")
}
