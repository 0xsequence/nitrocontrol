package encryption

import (
	"slices"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/sync/singleflight"
)

// CacheConfig configures the optional DEK (data encryption key) cache.
// A zero-value config disables caching.
type CacheConfig struct {
	// MaxSize is the maximum number of DEKs to cache. Must be > 0 to enable caching.
	MaxSize int
	// TTL is the time-to-live for each cache entry. Must be > 0 to enable caching.
	TTL time.Duration
}

// dekCache is an LRU of decrypted data encryption keys. Entries expire TTL
// after they are stored, regardless of use.
//
// Evicted keys are left for the garbage collector rather than zeroed. Zeroing
// would mean writing to a slice a concurrent reader may still be copying — the
// LRU releases its lock before the caller is done with the value, and the
// expiry sweeper runs on its own goroutine — which risks handing out a
// half-cleared key and failing a decryption. It buys little in return: the
// enclave already holds unscrubbed copies of this key from Shamir recombination
// and the AES key schedule, and its memory is neither swappable nor readable
// from the parent instance.
type dekCache struct {
	lru *expirable.LRU[string, []byte]
	// group collapses concurrent misses on the same keyRef into one load.
	group singleflight.Group
}

func newDEKCache(maxSize int, ttl time.Duration) *dekCache {
	return &dekCache{lru: expirable.NewLRU[string, []byte](maxSize, nil, ttl)}
}

// The cache and the caller each own their copy.
func (c *dekCache) get(keyRef string) ([]byte, bool) {
	dek, ok := c.lru.Get(keyRef)
	if !ok {
		return nil, false
	}
	return slices.Clone(dek), true
}

func (c *dekCache) put(keyRef string, dek []byte) {
	c.lru.Add(keyRef, slices.Clone(dek))
}

func (c *dekCache) delete(keyRef string) {
	c.lru.Remove(keyRef)
}
