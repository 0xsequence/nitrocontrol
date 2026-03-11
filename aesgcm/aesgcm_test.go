package aesgcm_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/0xsequence/nitrocontrol/aesgcm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncrypt(t *testing.T) {
	t.Run("no additional data", func(t *testing.T) {
		random := bytes.NewBuffer([]byte("123456789012")) // 12 bytes
		key := []byte("12345678901234567890123456789012") // 32 bytes
		plaintext := []byte("Hello world")
		enc, err := aesgcm.Encrypt(random, key[:], plaintext, nil)
		require.NoError(t, err)
		assert.Equal(t, "MTIzNDU2Nzg5MDEyyJeRgm1hto6XflsTaSRZcpV9masIpIeV/7/d", base64.StdEncoding.EncodeToString(enc))
	})

	t.Run("with additional data", func(t *testing.T) {
		random := bytes.NewBuffer([]byte("123456789012")) // 12 bytes
		key := []byte("12345678901234567890123456789012") // 32 bytes
		plaintext := []byte("Hello world")
		additionalData := []byte("additional data")
		enc, err := aesgcm.Encrypt(random, key[:], plaintext, additionalData)
		require.NoError(t, err)
		assert.Equal(t, "MTIzNDU2Nzg5MDEyyJeRgm1hto6XfluPj9+SAYdHVgK9WuQz9M6U", base64.StdEncoding.EncodeToString(enc))
	})
}

func TestDecrypt(t *testing.T) {
	t.Run("no additional data", func(t *testing.T) {
		key := []byte("12345678901234567890123456789012") // 32 bytes
		ciphertext, _ := base64.StdEncoding.DecodeString("MTIzNDU2Nzg5MDEyyJeRgm1hto6XflsTaSRZcpV9masIpIeV/7/d")
		dec, err := aesgcm.Decrypt(key, ciphertext, nil)
		require.NoError(t, err)
		assert.Equal(t, []byte("Hello world"), dec)
	})

	t.Run("with additional data", func(t *testing.T) {
		key := []byte("12345678901234567890123456789012") // 32 bytes
		ciphertext, _ := base64.StdEncoding.DecodeString("MTIzNDU2Nzg5MDEyyJeRgm1hto6XfluPj9+SAYdHVgK9WuQz9M6U")
		additionalData := []byte("additional data")
		dec, err := aesgcm.Decrypt(key, ciphertext, additionalData)
		require.NoError(t, err)
		assert.Equal(t, []byte("Hello world"), dec)
	})
}

func FuzzEncryptAndDecrypt(f *testing.F) {
	f.Add(uint64(0), uint64(0), uint64(0), uint64(0), []byte("hello"), []byte("aad"))
	f.Fuzz(func(t *testing.T, u0, u1, u2, u3 uint64, plaintext []byte, additionalData []byte) {
		key := make([]byte, 32)
		binary.LittleEndian.PutUint64(key, u0)
		binary.LittleEndian.PutUint64(key[8:], u1)
		binary.LittleEndian.PutUint64(key[16:], u2)
		binary.LittleEndian.PutUint64(key[24:], u3)

		enc, err := aesgcm.Encrypt(rand.Reader, key[:], plaintext, additionalData)
		require.NoError(t, err)
		require.Greater(t, len(enc), 16)

		dec, err := aesgcm.Decrypt(key, enc, additionalData)
		require.NoError(t, err)
		require.Equal(t, plaintext, dec)
	})
}
