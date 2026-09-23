package encryption

import (
	"sync"
	"testing"
	"time"
)

func TestDEKCache_GetPut(t *testing.T) {
	c := newDEKCache(10, time.Minute)
	dek := []byte("0123456789abcdef0123456789abcdef")

	c.put("ref1", dek)

	got, ok := c.get("ref1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if string(got) != string(dek) {
		t.Fatalf("got %x, want %x", got, dek)
	}

	// Returned slice must be an independent copy.
	got[0] = 0xFF
	got2, ok := c.get("ref1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got2[0] == 0xFF {
		t.Fatal("cache returned same underlying slice, expected independent copy")
	}

	// Stored slice must be an independent copy of the input.
	dek[0] = 0xAA
	got3, ok := c.get("ref1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got3[0] == 0xAA {
		t.Fatal("cache stored same underlying slice as input, expected independent copy")
	}
}

func TestDEKCache_Miss(t *testing.T) {
	c := newDEKCache(10, time.Minute)

	_, ok := c.get("unknown")
	if ok {
		t.Fatal("expected cache miss for unknown key")
	}
}

func TestDEKCache_TTLExpiry(t *testing.T) {
	c := newDEKCache(10, time.Millisecond)
	dek := []byte("0123456789abcdef0123456789abcdef")

	c.put("ref1", dek)

	// Grab internal slice before expiry.
	c.mu.Lock()
	internalSlice := c.entries["ref1"].dek
	c.mu.Unlock()

	time.Sleep(5 * time.Millisecond)

	_, ok := c.get("ref1")
	if ok {
		t.Fatal("expected cache miss after TTL expiry")
	}

	// Expired entry should be removed from map.
	c.mu.Lock()
	_, exists := c.entries["ref1"]
	c.mu.Unlock()
	if exists {
		t.Fatal("expired entry should have been removed from map")
	}

	// Internal DEK should be zeroed.
	for _, b := range internalSlice {
		if b != 0 {
			t.Fatal("expired DEK should have been zeroed")
		}
	}
}

func TestDEKCache_LRUEviction(t *testing.T) {
	c := newDEKCache(2, time.Minute)

	c.put("ref1", []byte("key1key1key1key1key1key1key1key1"))
	c.put("ref2", []byte("key2key2key2key2key2key2key2key2"))

	// Grab internal slice of ref2 before eviction.
	c.mu.Lock()
	internalRef2 := c.entries["ref2"].dek
	c.mu.Unlock()

	// Access ref1 to make it more recent than ref2.
	_, _ = c.get("ref1")

	// Adding ref3 should evict ref2 (LRU).
	c.put("ref3", []byte("key3key3key3key3key3key3key3key3"))

	if _, ok := c.get("ref2"); ok {
		t.Fatal("expected ref2 to be evicted (LRU)")
	}
	if _, ok := c.get("ref1"); !ok {
		t.Fatal("expected ref1 to still be cached")
	}
	if _, ok := c.get("ref3"); !ok {
		t.Fatal("expected ref3 to still be cached")
	}

	// Verify evicted internal DEK was zeroed.
	for _, b := range internalRef2 {
		if b != 0 {
			t.Fatal("evicted DEK should have been zeroed")
		}
	}
}

func TestDEKCache_PutUpdatesExisting(t *testing.T) {
	c := newDEKCache(10, time.Minute)
	dek1 := []byte("old_key_old_key_old_key_old_key_")
	dek2 := []byte("new_key_new_key_new_key_new_key_")

	c.put("ref1", dek1)

	// Grab internal slice and expiry before update.
	c.mu.Lock()
	internalSlice := c.entries["ref1"].dek
	oldExpiry := c.entries["ref1"].expiresAt
	c.mu.Unlock()

	time.Sleep(time.Millisecond) // ensure time advances
	c.put("ref1", dek2)

	got, ok := c.get("ref1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if string(got) != string(dek2) {
		t.Fatalf("got %x, want %x", got, dek2)
	}

	// Old internal slice should be zeroed.
	for _, b := range internalSlice {
		if b != 0 {
			t.Fatal("old DEK slice should have been zeroed")
		}
	}

	// TTL should be refreshed.
	c.mu.Lock()
	newExpiry := c.entries["ref1"].expiresAt
	c.mu.Unlock()
	if !newExpiry.After(oldExpiry) {
		t.Fatal("put on existing key should refresh TTL")
	}
}

func TestDEKCache_Delete(t *testing.T) {
	c := newDEKCache(10, time.Minute)
	dek := []byte("0123456789abcdef0123456789abcdef")

	c.put("ref1", dek)

	// Grab internal slice reference.
	c.mu.Lock()
	internalSlice := c.entries["ref1"].dek
	c.mu.Unlock()

	c.delete("ref1")

	if _, ok := c.get("ref1"); ok {
		t.Fatal("expected cache miss after delete")
	}

	// Verify zeroed.
	for _, b := range internalSlice {
		if b != 0 {
			t.Fatal("deleted DEK should have been zeroed")
		}
	}
}

func TestDEKCache_DeleteMissing(t *testing.T) {
	c := newDEKCache(10, time.Minute)
	// Should not panic.
	c.delete("nonexistent")
}

func TestDEKCache_ConcurrentAccess(t *testing.T) {
	c := newDEKCache(10, time.Minute)
	dek := []byte("0123456789abcdef0123456789abcdef")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func(n int) {
			defer wg.Done()
			c.put("ref1", dek)
		}(i)
		go func(n int) {
			defer wg.Done()
			c.get("ref1")
		}(i)
		go func(n int) {
			defer wg.Done()
			if n%10 == 0 {
				c.delete("ref1")
			}
		}(i)
	}
	wg.Wait()
}
