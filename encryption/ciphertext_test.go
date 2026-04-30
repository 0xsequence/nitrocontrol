package encryption

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCiphertext_Encode(t *testing.T) {
	tests := []struct {
		name          string
		version       int
		encryptedData []byte
		expected      string
		expectedError bool
		errorContains string
	}{
		{
			name:          "version 1 with simple data",
			version:       1,
			encryptedData: []byte("test-data"),
			expected:      "v1." + base64.RawURLEncoding.EncodeToString([]byte("test-data")),
		},
		{
			name:          "version 2 with simple data",
			version:       2,
			encryptedData: []byte("test-data"),
			expected:      "v2." + base64.RawURLEncoding.EncodeToString([]byte("test-data")),
		},
		{
			name:          "version 1 with empty data",
			version:       1,
			encryptedData: []byte{},
			expectedError: true,
			errorContains: "encrypted data cannot be empty",
		},
		{
			name:          "version 3 rejected by Encode",
			version:       3,
			encryptedData: []byte("test-data"),
			expectedError: true,
			errorContains: "unsupported version: 3",
		},
		{
			name:          "invalid version 0",
			version:       0,
			encryptedData: []byte("test-data"),
			expectedError: true,
			errorContains: "unsupported version: 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Ciphertext{Version: tt.version, EncryptedData: tt.encryptedData}
			result, err := c.Encode()
			if tt.expectedError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Empty(t, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestCiphertext_EncodeBinary(t *testing.T) {
	t.Run("v3 with data", func(t *testing.T) {
		c := &Ciphertext{Version: 3, EncryptedData: []byte{0xAA, 0xBB, 0xCC}}
		out, err := c.EncodeBinary()
		require.NoError(t, err)
		assert.Equal(t, []byte{0x03, 0xAA, 0xBB, 0xCC}, out)
	})

	t.Run("v3 with empty data", func(t *testing.T) {
		c := &Ciphertext{Version: 3, EncryptedData: []byte{}}
		_, err := c.EncodeBinary()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encrypted data cannot be empty")
	})

	t.Run("v2 rejected", func(t *testing.T) {
		c := &Ciphertext{Version: 2, EncryptedData: []byte("data")}
		_, err := c.EncodeBinary()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "EncodeBinary only supports version 3")
	})

	t.Run("v1 rejected", func(t *testing.T) {
		c := &Ciphertext{Version: 1, EncryptedData: []byte("data")}
		_, err := c.EncodeBinary()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "EncodeBinary only supports version 3")
	})
}

func TestDecodeCiphertext(t *testing.T) {
	tests := []struct {
		name          string
		ciphertext    string
		expectedVer   int
		expectedData  []byte
		expectedError bool
		errorContains string
	}{
		{
			name:         "valid v1 ciphertext",
			ciphertext:   "v1." + base64.RawURLEncoding.EncodeToString([]byte("test-data")),
			expectedVer:  1,
			expectedData: []byte("test-data"),
		},
		{
			name:          "invalid - empty data",
			ciphertext:    "v1.",
			expectedError: true,
			errorContains: "encrypted data cannot be empty",
		},
		{
			name:          "invalid - no separator",
			ciphertext:    "v1testdata",
			expectedError: true,
			errorContains: "invalid ciphertext",
		},
		{
			name:          "invalid - unsupported version v3",
			ciphertext:    "v3." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedError: true,
			errorContains: "unsupported ciphertext version: v3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DecodeCiphertext(tt.ciphertext)
			if tt.expectedError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tt.expectedVer, result.Version)
				assert.Equal(t, tt.expectedData, result.EncryptedData)
			}
		})
	}
}

func TestDecodeCiphertextBytes(t *testing.T) {
	t.Run("legacy v1 string", func(t *testing.T) {
		ct := []byte("v1." + base64.RawURLEncoding.EncodeToString([]byte("test-data")))
		result, err := DecodeCiphertextBytes(ct)
		require.NoError(t, err)
		assert.Equal(t, 1, result.Version)
		assert.Equal(t, []byte("test-data"), result.EncryptedData)
	})

	t.Run("legacy v2 string", func(t *testing.T) {
		ct := []byte("v2." + base64.RawURLEncoding.EncodeToString([]byte("test-data")))
		result, err := DecodeCiphertextBytes(ct)
		require.NoError(t, err)
		assert.Equal(t, 2, result.Version)
		assert.Equal(t, []byte("test-data"), result.EncryptedData)
	})

	t.Run("v3 binary", func(t *testing.T) {
		ct := append([]byte{0x03}, []byte("raw-encrypted-data")...)
		result, err := DecodeCiphertextBytes(ct)
		require.NoError(t, err)
		assert.Equal(t, 3, result.Version)
		assert.Equal(t, []byte("raw-encrypted-data"), result.EncryptedData)
	})

	t.Run("v3 binary roundtrip", func(t *testing.T) {
		original := &Ciphertext{Version: 3, EncryptedData: []byte{0xDE, 0xAD, 0xBE, 0xEF}}
		encoded, err := original.EncodeBinary()
		require.NoError(t, err)

		decoded, err := DecodeCiphertextBytes(encoded)
		require.NoError(t, err)
		assert.Equal(t, original.Version, decoded.Version)
		assert.Equal(t, original.EncryptedData, decoded.EncryptedData)
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := DecodeCiphertextBytes(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty ciphertext")
	})

	t.Run("v3 too short", func(t *testing.T) {
		_, err := DecodeCiphertextBytes([]byte{0x03})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "v3 ciphertext too short")
	})

	t.Run("unsupported first byte", func(t *testing.T) {
		_, err := DecodeCiphertextBytes([]byte{0xFF, 0x01, 0x02})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported ciphertext format: first byte 0xff")
	})
}

func TestCiphertext_EncodeDecode_Roundtrip(t *testing.T) {
	// String format roundtrip (v1, v2)
	for _, version := range []int{1, 2} {
		c := &Ciphertext{Version: version, EncryptedData: []byte("encrypted-data")}
		encoded, err := c.Encode()
		require.NoError(t, err)

		decoded, err := DecodeCiphertext(encoded)
		require.NoError(t, err)
		assert.Equal(t, c.Version, decoded.Version)
		assert.Equal(t, c.EncryptedData, decoded.EncryptedData)

		// Also via DecodeCiphertextBytes
		decoded2, err := DecodeCiphertextBytes([]byte(encoded))
		require.NoError(t, err)
		assert.Equal(t, c.Version, decoded2.Version)
		assert.Equal(t, c.EncryptedData, decoded2.EncryptedData)
	}
}
