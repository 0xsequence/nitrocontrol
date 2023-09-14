package aescbc_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xsequence/nitrocontrol/aescbc"
)

func TestEncrypt(t *testing.T) {
	iv := bytes.NewBuffer([]byte("1234567890123456")) // 16 bytes
	key := []byte("12345678901234567890123456789012") // 32 bytes
	plaintext := []byte("Hello world")
	enc, err := aescbc.Encrypt(iv, key[:], plaintext)
	require.NoError(t, err)
	assert.Equal(t, "MTIzNDU2Nzg5MDEyMzQ1Ni+w5YFadsnxR4rHC8t64vM=", base64.StdEncoding.EncodeToString(enc))
}

func TestDecrypt(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32 bytes
	ciphertext, _ := base64.StdEncoding.DecodeString("MTIzNDU2Nzg5MDEyMzQ1Ni+w5YFadsnxR4rHC8t64vM=")
	dec, err := aescbc.Decrypt(key, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, []byte("Hello world"), dec)
}

func FuzzEncryptAndDecrypt(f *testing.F) {
	f.Add(uint64(0), uint64(0), uint64(0), uint64(0), []byte("hello"))
	f.Fuzz(func(t *testing.T, u0, u1, u2, u3 uint64, plaintext []byte) {
		key := make([]byte, 32)
		binary.LittleEndian.PutUint64(key, u0)
		binary.LittleEndian.PutUint64(key[8:], u1)
		binary.LittleEndian.PutUint64(key[16:], u2)
		binary.LittleEndian.PutUint64(key[24:], u3)

		enc, err := aescbc.Encrypt(rand.Reader, key[:], plaintext)
		require.NoError(t, err)
		require.Greater(t, len(enc), 16)

		dec, err := aescbc.Decrypt(key, enc)
		require.NoError(t, err)
		require.Equal(t, plaintext, dec)
	})
}
