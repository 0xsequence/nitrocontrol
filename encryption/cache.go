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
	// MaxSize is the maximum number of DEKs to cache.
	MaxSize int
	// TTL is how long a cached DEK lives, counted from when it is stored.
	TTL time.Duration
}

// dekCache is an LRU of decrypted data encryption keys.
//
// Evicted keys are not zeroed: the LRU releases its lock before the caller has
// finished copying a value, so clearing one risks handing out a half-cleared
// key. The enclave already holds unscrubbed copies from Shamir recombination
// and the AES key schedule.
type dekCache struct {
	lru *expirable.LRU[string, []byte]
	// group collapses concurrent misses on the same keyRef into one load.
	group singleflight.Group
}

func newDEKCache(maxSize int, ttl time.Duration) *dekCache {
	return &dekCache{lru: expirable.NewLRU[string, []byte](maxSize, nil, ttl)}
}

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
