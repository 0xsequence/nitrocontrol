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

func TestDEKCache_Clear(t *testing.T) {
	c := newDEKCache(10, time.Minute)

	dek1 := []byte("key1key1key1key1key1key1key1key1")
	dek2 := []byte("key2key2key2key2key2key2key2key2")
	c.put("ref1", dek1)
	c.put("ref2", dek2)

	// Grab internal slice references.
	c.mu.Lock()
	internal1 := c.entries["ref1"].dek
	internal2 := c.entries["ref2"].dek
	c.mu.Unlock()

	c.clear()

	if _, ok := c.get("ref1"); ok {
		t.Fatal("expected miss after clear")
	}
	if _, ok := c.get("ref2"); ok {
		t.Fatal("expected miss after clear")
	}

	for _, b := range internal1 {
		if b != 0 {
			t.Fatal("cleared DEK 1 should be zeroed")
		}
	}
	for _, b := range internal2 {
		if b != 0 {
			t.Fatal("cleared DEK 2 should be zeroed")
		}
	}
}

func TestDEKCache_ClearThenReuse(t *testing.T) {
	c := newDEKCache(10, time.Minute)
	dek := []byte("0123456789abcdef0123456789abcdef")

	c.put("ref1", dek)
	c.clear()

	// Cache should work normally after clear.
	c.put("ref1", dek)
	got, ok := c.get("ref1")
	if !ok {
		t.Fatal("expected cache hit after clear + put")
	}
	if string(got) != string(dek) {
		t.Fatalf("got %x, want %x", got, dek)
	}
}

func TestDEKCache_Singleflight(t *testing.T) {
	c := newDEKCache(10, time.Minute)

	dek := []byte("0123456789abcdef0123456789abcdef")

	// First caller starts the fetch.
	started, _ := c.waitOrStart("ref1")
	if !started {
		t.Fatal("first caller should start")
	}

	// Second and third callers should wait.
	var wg sync.WaitGroup
	results := make([][]byte, 2)
	errs := make([]error, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			s, wait := c.waitOrStart("ref1")
			if s {
				t.Error("subsequent caller should not start")
				return
			}
			results[idx], errs[idx] = wait()
		}(i)
	}

	// Simulate fetch completing.
	time.Sleep(10 * time.Millisecond) // let goroutines reach wait()
	c.finish("ref1", dek, nil)

	wg.Wait()

	for i := 0; i < 2; i++ {
		if errs[i] != nil {
			t.Fatalf("waiter %d got error: %v", i, errs[i])
		}
		if string(results[i]) != string(dek) {
			t.Fatalf("waiter %d got wrong dek", i)
		}
	}

	// Each waiter should have received an independent copy.
	results[0][0] = 0xFF
	if results[1][0] == 0xFF {
		t.Fatal("waiters should receive independent copies")
	}
}

func TestDEKCache_SingleflightError(t *testing.T) {
	c := newDEKCache(10, time.Minute)
	fetchErr := &testError{msg: "kms failed"}

	started, _ := c.waitOrStart("ref1")
	if !started {
		t.Fatal("first caller should start")
	}

	var wg sync.WaitGroup
	waiterErrs := make([]error, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, wait := c.waitOrStart("ref1")
			_, waiterErrs[idx] = wait()
		}(i)
	}

	time.Sleep(10 * time.Millisecond)
	c.finish("ref1", nil, fetchErr)

	wg.Wait()

	for i := 0; i < 2; i++ {
		if waiterErrs[i] == nil {
			t.Fatalf("waiter %d should have received error", i)
		}
		if waiterErrs[i].Error() != "kms failed" {
			t.Fatalf("waiter %d got error %q, want %q", i, waiterErrs[i].Error(), "kms failed")
		}
	}
}

func TestDEKCache_SingleflightIndependentKeys(t *testing.T) {
	c := newDEKCache(10, time.Minute)

	dek1 := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	dek2 := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	// Start fetch for ref1.
	started1, _ := c.waitOrStart("ref1")
	if !started1 {
		t.Fatal("first caller for ref1 should start")
	}

	// Start fetch for ref2 — should NOT be blocked by ref1.
	started2, _ := c.waitOrStart("ref2")
	if !started2 {
		t.Fatal("first caller for ref2 should start independently")
	}

	c.finish("ref1", dek1, nil)
	c.finish("ref2", dek2, nil)
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

type testError struct {
	msg string
}

func (e *testError) Error() string { return e.msg }
