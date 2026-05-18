package encryption

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/stretchr/testify/require"
)

type stubRemoteKey struct{ id string }

func (k *stubRemoteKey) RemoteKeyID() string { return k.id }
func (k *stubRemoteKey) Encrypt(_ context.Context, _ *enclave.Attestation, _ []byte) (string, error) {
	return "", nil
}
func (k *stubRemoteKey) Decrypt(_ context.Context, _ *enclave.Attestation, _ string) ([]byte, error) {
	return nil, nil
}

func TestNewConfig(t *testing.T) {
	keys := []RemoteKey{
		&stubRemoteKey{id: "key1"},
		&stubRemoteKey{id: "key2"},
		&stubRemoteKey{id: "key3"},
	}

	t.Run("valid config", func(t *testing.T) {
		cfg, err := NewConfig(10, 2, keys)
		require.NoError(t, err)
		require.Equal(t, 10, cfg.PoolSize)
		require.Equal(t, 2, cfg.Threshold)
		require.Len(t, cfg.RemoteKeys, 3)
	})

	t.Run("zero pool size", func(t *testing.T) {
		_, err := NewConfig(0, 2, keys)
		require.ErrorContains(t, err, "poolSize must be at least 1")
	})

	t.Run("negative pool size", func(t *testing.T) {
		_, err := NewConfig(-1, 2, keys)
		require.ErrorContains(t, err, "poolSize must be at least 1")
	})

	t.Run("threshold too low", func(t *testing.T) {
		_, err := NewConfig(10, 1, keys)
		require.ErrorContains(t, err, "threshold must be at least 2")
	})

	t.Run("threshold zero", func(t *testing.T) {
		_, err := NewConfig(10, 0, keys)
		require.ErrorContains(t, err, "threshold must be at least 2")
	})

	t.Run("not enough keys for threshold", func(t *testing.T) {
		_, err := NewConfig(10, 3, keys[:2])
		require.ErrorContains(t, err, "number of keys (2) must be at least threshold (3)")
	})

	t.Run("exact threshold keys", func(t *testing.T) {
		cfg, err := NewConfig(10, 2, keys[:2])
		require.NoError(t, err)
		require.Len(t, cfg.RemoteKeys, 2)
	})
}

func TestConfig_areSharesValid(t *testing.T) {
	config := &Config{
		RemoteKeys: map[string]RemoteKey{
			"key1": nil,
			"key2": nil,
		},
	}

	t.Run("valid shares", func(t *testing.T) {
		shares := map[string]string{"key1": "share1", "key2": "share2"}
		require.True(t, config.areSharesValid(shares))
	})

	t.Run("extra share", func(t *testing.T) {
		shares := map[string]string{"key1": "share1", "key2": "share2", "key3": "share3"}
		require.False(t, config.areSharesValid(shares))
	})

	t.Run("missing share", func(t *testing.T) {
		shares := map[string]string{"key1": "share1"}
		require.False(t, config.areSharesValid(shares))
	})

	t.Run("wrong share keys", func(t *testing.T) {
		shares := map[string]string{"key1": "share1", "keyX": "shareX"}
		require.False(t, config.areSharesValid(shares))
	})

	t.Run("empty shares", func(t *testing.T) {
		shares := map[string]string{}
		require.False(t, config.areSharesValid(shares))
	})

	t.Run("both empty", func(t *testing.T) {
		emptyConfig := &Config{RemoteKeys: map[string]RemoteKey{}}
		require.True(t, emptyConfig.areSharesValid(map[string]string{}))
	})

	t.Run("nil shares", func(t *testing.T) {
		require.False(t, config.areSharesValid(nil))
	})
}

func TestConfig_randomKeyIndex(t *testing.T) {
	t.Run("deterministic with constant reader", func(t *testing.T) {
		config := &Config{PoolSize: 10}
		reader := bytes.NewReader([]byte{0x00, 0x00, 0x00, 0x2A}) // 42 in big-endian
		idx, err := config.randomKeyIndex(reader)
		require.NoError(t, err)
		require.Equal(t, 42%10, idx) // 42 mod 10 = 2
	})

	t.Run("result is within range", func(t *testing.T) {
		config := &Config{PoolSize: 7}
		// 0xFF * 4 bytes = 0xFFFFFFFF = 4294967295, mod 7 = 3
		reader := bytes.NewReader([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		idx, err := config.randomKeyIndex(reader)
		require.NoError(t, err)
		require.GreaterOrEqual(t, idx, 0)
		require.Less(t, idx, 7)
	})

	t.Run("pool size 1 always returns 0", func(t *testing.T) {
		config := &Config{PoolSize: 1}
		reader := bytes.NewReader([]byte{0xAB, 0xCD, 0xEF, 0x12})
		idx, err := config.randomKeyIndex(reader)
		require.NoError(t, err)
		require.Equal(t, 0, idx)
	})

	t.Run("reader error", func(t *testing.T) {
		config := &Config{PoolSize: 10}
		reader := &errorReader{err: errors.New("entropy exhausted")}
		_, err := config.randomKeyIndex(reader)
		require.Error(t, err)
		require.ErrorContains(t, err, "entropy exhausted")
	})

	t.Run("short reader", func(t *testing.T) {
		config := &Config{PoolSize: 10}
		reader := bytes.NewReader([]byte{0x01, 0x02}) // only 2 bytes, need 4
		_, err := config.randomKeyIndex(reader)
		require.Error(t, err)
	})
}

type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (int, error) {
	return 0, r.err
}
