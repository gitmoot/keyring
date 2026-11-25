package server

import (
	"bytes"
	"errors"
	"testing"
)

// #198: a full HTTP/1.0 answer must not hold more memory than its limit.
func TestCappedBufferNeverHoldsMoreThanItsLimit(t *testing.T) {
	const limit = 3<<20 + 123
	b := &cappedBuffer{max: limit}
	chunk := bytes.Repeat([]byte("x"), 32<<10)
	for b.Len()+len(chunk) <= limit {
		if _, err := b.Write(chunk); err != nil {
			t.Fatalf("write within the limit refused at %d: %v", b.Len(), err)
		}
		if cap(b.buf) > limit {
			t.Fatalf("capacity %d exceeds limit %d at length %d", cap(b.buf), limit, b.Len())
		}
	}
	rest := limit - b.Len()
	if _, err := b.Write(chunk[:rest]); err != nil {
		t.Fatalf("filling to exactly the limit refused: %v", err)
	}
	if _, err := b.Write([]byte("y")); !errors.Is(err, errAnswerTooLarge) {
		t.Fatalf("write past the limit: %v, want errAnswerTooLarge", err)
	}
	if b.Len() != limit || cap(b.buf) > limit || !bytes.Equal(b.Bytes(), bytes.Repeat([]byte("x"), limit)) {
		t.Fatalf("len %d cap %d after filling, want len and cap %d with the written bytes", b.Len(), cap(b.buf), limit)
	}
}
