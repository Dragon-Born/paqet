package socket

import (
	"testing"
)

func TestRandRangeBounds(t *testing.T) {
	for i := 0; i < 1000; i++ {
		v := randRange(60, 68)
		if v < 60 || v > 68 {
			t.Fatalf("randRange(60, 68) = %d, out of bounds", v)
		}
	}
}

func TestRandRangeSingleValue(t *testing.T) {
	for i := 0; i < 100; i++ {
		v := randRange(5, 5)
		if v != 5 {
			t.Fatalf("randRange(5, 5) = %d, expected 5", v)
		}
	}
}

func TestRandRangeDistribution(t *testing.T) {
	// Verify that over many iterations, we see at least two distinct values
	seen := make(map[int]bool)
	for i := 0; i < 100; i++ {
		seen[randRange(0, 9)] = true
	}
	if len(seen) < 2 {
		t.Fatalf("randRange(0,9) produced only %d distinct values over 100 iterations", len(seen))
	}
}

func TestRandUint32NonConstant(t *testing.T) {
	seen := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		seen[randUint32()] = true
	}
	if len(seen) < 50 {
		t.Fatalf("randUint32 produced only %d distinct values over 100 calls", len(seen))
	}
}

func TestTOSChoicesValid(t *testing.T) {
	validTOS := map[uint8]bool{0x00: true, 0x10: true, 0x08: true}
	tosChoices := []uint8{0x00, 0x10, 0x08}

	for i := 0; i < 100; i++ {
		idx := randRange(0, len(tosChoices)-1)
		tos := tosChoices[idx]
		if !validTOS[tos] {
			t.Fatalf("unexpected TOS value: 0x%02x", tos)
		}
	}
}

func TestTTLRange(t *testing.T) {
	for i := 0; i < 1000; i++ {
		ttl := uint8(randRange(60, 68))
		if ttl < 60 || ttl > 68 {
			t.Fatalf("TTL %d out of range [60,68]", ttl)
		}
	}
}

func TestWindowRange(t *testing.T) {
	for i := 0; i < 1000; i++ {
		win := uint16(randRange(64240, 65535))
		if win < 64240 || win > 65535 {
			t.Fatalf("Window %d out of range [64240,65535]", win)
		}
	}
}

func TestSeqNumbersNotRepeating(t *testing.T) {
	// Simulate the non-SYN sequence generation pattern
	baseSeq := randUint32()
	seen := make(map[uint32]bool)
	for counter := uint32(1); counter <= 100; counter++ {
		seq := baseSeq + counter*1460
		if seen[seq] {
			t.Fatalf("duplicate seq at counter=%d", counter)
		}
		seen[seq] = true
	}
}

func TestSYNSeqFullyRandom(t *testing.T) {
	seen := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		seen[randUint32()] = true
	}
	// With 32-bit random values, 100 draws should all be unique with overwhelming probability
	if len(seen) < 95 {
		t.Fatalf("SYN sequence numbers not sufficiently random: only %d unique of 100", len(seen))
	}
}
