package kms

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCiphertext_Encode(t *testing.T) {
	tests := []struct {
		name          string
		encryptedKey  []byte
		encryptedData []byte
		expected      string
		expectedError bool
		errorContains string
	}{
		{
			name:          "empty key",
			encryptedKey:  []byte{},
			encryptedData: []byte("data"),
			expectedError: true,
			errorContains: "encrypted key cannot be empty",
		},
		{
			name:          "empty data",
			encryptedKey:  []byte("key"),
			encryptedData: []byte{},
			expectedError: true,
			errorContains: "encrypted data cannot be empty",
		},
		{
			name:          "simple data",
			encryptedKey:  []byte("key"),
			encryptedData: []byte("data"),
			expected:      base64.RawURLEncoding.EncodeToString([]byte("key")) + "." + base64.RawURLEncoding.EncodeToString([]byte("data")),
		},
		{
			name:          "binary data",
			encryptedKey:  []byte{0x00, 0x01, 0x02, 0x03},
			encryptedData: []byte{0xFF, 0xFE, 0xFD, 0xFC},
			expected:      base64.RawURLEncoding.EncodeToString([]byte{0x00, 0x01, 0x02, 0x03}) + "." + base64.RawURLEncoding.EncodeToString([]byte{0xFF, 0xFE, 0xFD, 0xFC}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Ciphertext{
				EncryptedKey:  tt.encryptedKey,
				EncryptedData: tt.encryptedData,
			}
			result, err := c.Encode()

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Empty(t, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestDecodeCiphertext(t *testing.T) {
	tests := []struct {
		name          string
		ciphertext    string
		expectedKey   []byte
		expectedData  []byte
		expectedError bool
		errorContains string
	}{
		{
			name:         "valid simple ciphertext",
			ciphertext:   base64.RawURLEncoding.EncodeToString([]byte("key")) + "." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedKey:  []byte("key"),
			expectedData: []byte("data"),
		},
		{
			name:          "invalid - no separator",
			ciphertext:    "invalidciphertext",
			expectedError: true,
			errorContains: "invalid ciphertext",
		},
		{
			name:          "invalid - too many parts",
			ciphertext:    "part1.part2.part3",
			expectedError: true,
			errorContains: "invalid ciphertext",
		},
		{
			name:          "invalid - empty string",
			ciphertext:    "",
			expectedError: true,
			errorContains: "invalid ciphertext",
		},
		{
			name:          "invalid - empty key",
			ciphertext:    "." + base64.RawURLEncoding.EncodeToString([]byte("data")),
			expectedError: true,
			errorContains: "encrypted key cannot be empty",
		},
		{
			name:          "invalid - empty data",
			ciphertext:    base64.RawURLEncoding.EncodeToString([]byte("key")) + ".",
			expectedError: true,
			errorContains: "encrypted data cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DecodeCiphertext(tt.ciphertext)

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tt.expectedKey, result.EncryptedKey)
				assert.Equal(t, tt.expectedData, result.EncryptedData)
			}
		})
	}
}

func TestCiphertext_EncodeDecode_Roundtrip(t *testing.T) {
	original := &Ciphertext{
		EncryptedKey:  []byte("encryption-key"),
		EncryptedData: []byte("sensitive-data"),
	}

	encoded, err := original.Encode()
	require.NoError(t, err)

	decoded, err := DecodeCiphertext(encoded)
	require.NoError(t, err)

	assert.Equal(t, original.EncryptedKey, decoded.EncryptedKey)
	assert.Equal(t, original.EncryptedData, decoded.EncryptedData)
}
