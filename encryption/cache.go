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
	// Values below minCacheTTL disable the cache.
	TTL time.Duration
}

// minCacheTTL keeps expirable.LRU's eviction ticker, which runs at TTL/100,
// above 10ms. Below 100ns it panics outright, and a bare integer literal is a
// legal time.Duration, so a TTL meant as seconds lands in that range.
const minCacheTTL = time.Second

type dekCache struct {
	lru   *expirable.LRU[string, []byte]
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
