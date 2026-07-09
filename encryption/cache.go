package encryption

import (
	"container/list"
	"sync"
	"time"
)

// CacheConfig configures the optional DEK (data encryption key) cache.
// A zero-value config disables caching.
type CacheConfig struct {
	// MaxSize is the maximum number of DEKs to cache. Must be > 0 to enable caching.
	MaxSize int
	// TTL is the time-to-live for each cache entry. Must be > 0 to enable caching.
	TTL time.Duration
}

// dekCacheEntry holds a cached DEK and its LRU/TTL metadata.
type dekCacheEntry struct {
	dek       []byte        // 32-byte AES-256 key (owned copy)
	keyRef    string        // for reverse lookup from LRU list element
	expiresAt time.Time
	element   *list.Element // back-pointer into LRU list
}

// dekCache is a thread-safe LRU cache for decrypted data encryption keys.
// It zeroes key material on every eviction path (TTL, LRU, delete, clear).
type dekCache struct {
	mu      sync.Mutex
	entries map[string]*dekCacheEntry
	order   *list.List // front = most recently used
	maxSize int
	ttl     time.Duration

	inflightMu sync.Mutex
	inflight   map[string]*inflightEntry
}

// inflightEntry coordinates singleflight deduplication for concurrent
// cache misses on the same keyRef.
type inflightEntry struct {
	done chan struct{}
	dek  []byte
	err  error
}

func newDEKCache(maxSize int, ttl time.Duration) *dekCache {
	return &dekCache{
		entries:  make(map[string]*dekCacheEntry),
		order:    list.New(),
		maxSize:  maxSize,
		ttl:      ttl,
		inflight: make(map[string]*inflightEntry),
	}
}

// get returns a copy of the cached DEK for keyRef, or ok=false on miss/expiry.
func (c *dekCache) get(keyRef string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[keyRef]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		c.evictLocked(entry)
		return nil, false
	}

	c.order.MoveToFront(entry.element)
	return copyBytes(entry.dek), true
}

// put stores a copy of dek in the cache, evicting the LRU entry if full.
func (c *dekCache) put(keyRef string, dek []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.entries[keyRef]; ok {
		// Update existing entry.
		clear(entry.dek)
		entry.dek = copyBytes(dek)
		entry.expiresAt = time.Now().Add(c.ttl)
		c.order.MoveToFront(entry.element)
		return
	}

	entry := &dekCacheEntry{
		dek:       copyBytes(dek),
		keyRef:    keyRef,
		expiresAt: time.Now().Add(c.ttl),
	}
	entry.element = c.order.PushFront(entry)
	c.entries[keyRef] = entry

	if len(c.entries) > c.maxSize {
		back := c.order.Back()
		if back != nil {
			c.evictLocked(back.Value.(*dekCacheEntry))
		}
	}
}

// delete removes and zeroes a specific entry. Called by RotateKey.
func (c *dekCache) delete(keyRef string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.entries[keyRef]; ok {
		c.evictLocked(entry)
	}
}

// clear removes and zeroes all entries.
func (c *dekCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, entry := range c.entries {
		clear(entry.dek)
	}
	c.entries = make(map[string]*dekCacheEntry)
	c.order.Init()
}

// evictLocked removes an entry, zeroing its DEK. Caller must hold c.mu.
func (c *dekCache) evictLocked(entry *dekCacheEntry) {
	clear(entry.dek)
	c.order.Remove(entry.element)
	delete(c.entries, entry.keyRef)
}

// waitOrStart implements singleflight deduplication. If another goroutine is
// already fetching the DEK for keyRef, started=false and wait blocks until the
// result is available. Otherwise started=true and the caller must call finish.
func (c *dekCache) waitOrStart(keyRef string) (started bool, wait func() ([]byte, error)) {
	c.inflightMu.Lock()

	if entry, ok := c.inflight[keyRef]; ok {
		c.inflightMu.Unlock()
		return false, func() ([]byte, error) {
			<-entry.done
			if entry.err != nil {
				return nil, entry.err
			}
			return copyBytes(entry.dek), nil
		}
	}

	entry := &inflightEntry{done: make(chan struct{})}
	c.inflight[keyRef] = entry
	c.inflightMu.Unlock()

	return true, nil
}

// finish signals all waiters for keyRef with the fetch result.
func (c *dekCache) finish(keyRef string, dek []byte, err error) {
	c.inflightMu.Lock()
	entry, ok := c.inflight[keyRef]
	if ok {
		entry.dek = copyBytes(dek)
		entry.err = err
		close(entry.done)
		delete(c.inflight, keyRef)
	}
	c.inflightMu.Unlock()
}

func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp
}
