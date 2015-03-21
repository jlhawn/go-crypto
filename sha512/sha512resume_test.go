package sha512

import (
	"bytes"
	"crypto/rand"
	"github.com/jlhawn/go-crypto"
	"io"
	"testing"
)

func compareResumableHash(t *testing.T, h crypto.Hash) {
	// Read 3 Kilobytes of random data into a buffer.
	buf := make([]byte, 3*1024)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		t.Fatalf("unable to load random data: %s", err)
	}

	// Use two Hash objects to consume prefixes of the data. One will be
	// snapshotted and resumed with each new chunk, the other will be reset
	// from the beginning each time. The digests should be equal after each
	// chunk is digested.
	fullHasher := h.New()
	chunkHasher := h.New()

	for i := 0; i <= len(buf); i++ {
		l := i - 1
		if l < 0 {
			l = 0
		}

		chunkHasher.Write(buf[l:i])
		fullHasher.Write(buf[:i])

		if !bytes.Equal(chunkHasher.Sum(nil), fullHasher.Sum(nil)) {
			t.Fatalf("digests do not match: got %x, expected %x", chunkHasher.Sum(nil), fullHasher.Sum(nil))
		}

		hashState, err := chunkHasher.State()
		if err != nil {
			t.Fatalf("unable to get state of hash function: %s", err)
		}

		chunkHasher.Reset()
		fullHasher.Reset()

		if err := chunkHasher.Restore(hashState); err != nil {
			t.Fatalf("unable to restorte state of hash function: %s", err)
		}
	}
}

func TestResumable(t *testing.T) {
	compareResumableHash(t, crypto.SHA384)
	compareResumableHash(t, crypto.SHA512)
}
