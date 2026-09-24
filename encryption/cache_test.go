package encryption

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDEKCache_GetPut(t *testing.T) {
	c := newDEKCache(10, time.Minute)
	dek := []byte("0123456789abcdef0123456789abcdef")

	c.put("ref1", dek)

	got, ok := c.get("ref1")
	require.True(t, ok, "expected cache hit")
	require.Equal(t, dek, got)

	// Returned slice must be an independent copy.
	got[0] = 0xFF
	got2, _ := c.get("ref1")
	require.NotEqual(t, byte(0xFF), got2[0], "cache returned same underlying slice, expected independent copy")

	// Stored slice must be an independent copy of the input.
	dek[0] = 0xAA
	got3, _ := c.get("ref1")
	require.NotEqual(t, byte(0xAA), got3[0], "cache stored same underlying slice as input, expected independent copy")
}

func TestDEKCache_Miss(t *testing.T) {
	c := newDEKCache(10, time.Minute)

	_, ok := c.get("unknown")
	require.False(t, ok, "expected cache miss for unknown key")
}

func TestDEKCache_TTLExpiry(t *testing.T) {
	c := newDEKCache(10, time.Millisecond)
	c.put("ref1", []byte("0123456789abcdef0123456789abcdef"))

	time.Sleep(5 * time.Millisecond)

	_, ok := c.get("ref1")
	require.False(t, ok, "expected cache miss after TTL expiry")
}

func TestDEKCache_LRUEviction(t *testing.T) {
	c := newDEKCache(2, time.Minute)

	c.put("ref1", []byte("key1key1key1key1key1key1key1key1"))
	c.put("ref2", []byte("key2key2key2key2key2key2key2key2"))

	// Make ref1 more recent than ref2, so ref3 evicts ref2.
	_, _ = c.get("ref1")
	c.put("ref3", []byte("key3key3key3key3key3key3key3key3"))

	_, ok := c.get("ref2")
	require.False(t, ok, "expected ref2 to be evicted (LRU)")
	_, ok = c.get("ref1")
	require.True(t, ok, "expected ref1 to still be cached")
	_, ok = c.get("ref3")
	require.True(t, ok, "expected ref3 to still be cached")
}

func TestDEKCache_PutUpdatesExisting(t *testing.T) {
	c := newDEKCache(10, time.Minute)
	dek2 := []byte("new_key_new_key_new_key_new_key_")

	c.put("ref1", []byte("old_key_old_key_old_key_old_key_"))
	c.put("ref1", dek2)

	got, ok := c.get("ref1")
	require.True(t, ok, "expected cache hit")
	require.Equal(t, dek2, got)
}

func TestDEKCache_Delete(t *testing.T) {
	c := newDEKCache(10, time.Minute)

	c.put("ref1", []byte("0123456789abcdef0123456789abcdef"))
	c.delete("ref1")

	_, ok := c.get("ref1")
	require.False(t, ok, "expected cache miss after delete")
}

func TestDEKCache_DeleteMissing(t *testing.T) {
	c := newDEKCache(10, time.Minute)
	c.delete("nonexistent")
}

func TestDEKCache_ConcurrentAccess(t *testing.T) {
	c := newDEKCache(10, time.Minute)
	dek := []byte("0123456789abcdef0123456789abcdef")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			c.put("ref1", dek)
		}()
		go func() {
			defer wg.Done()
			c.get("ref1")
		}()
		go func(n int) {
			defer wg.Done()
			if n%10 == 0 {
				c.delete("ref1")
			}
		}(i)
	}
	wg.Wait()
}
