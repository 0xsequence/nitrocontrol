package encryption_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/0xsequence/nitrocontrol/encryption"
	"github.com/0xsequence/nitrocontrol/encryption/data"
	"github.com/0xsequence/nitrocontrol/encryption/shamir"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var dummyPrivKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAujDWnWEKVYoHUwieLegkzR2K+4z2Fg3uVEwmZ16iRJiYm5TO
ltLN6BSHaLCqreA1bYXXTFlIG10z2+h16fhkCNKzy4yKwjwUdXJlbBivypQers8h
Pwy1l4c+uID/VX5zXG4y7g7aNc0Ude+lzBvydh9vFz5PwupFzY6ok3czI95ODni7
hn/X/8TBGTyh0eYZu8ehfKy6W9AHbX7D+yL2qebSWWkJBEribptpCcaJi8QPUx9M
HWz8j1j83+M6rnG1FQpLl8VNOO6BXmzb5FNr+6lwEfvwHbht0Azhk0ArMQZ/r0lO
ObAvVDmE2AuudXyWWh5sRrXnXlVitDjTQybQAQIDAQABAoIBAQCYf9Poh0jdkvY4
zkAwvYkW73GcY3JT0gk4xj5WQC6MHKgyFgm3guXfhqD54GmLjK52DD+xaxciQo5t
OdMKVcYpa9qTh4NHX8oqAA6OIRIqzHLtHv3OFGzPtZhrqkx4C+AU/rV8QnH7ywNN
LYIQ0XsfwNNOqFzP+u49VPFCB0m9v7r7mJxeUXp8PDfdhquFT69hpKwNdpzuIDA7
kVOG4ATkkPTGp3AmJj9Vrit9ffi+xlbhrNIuBui9Fxo1v5G6VT2uBhXJU22zl1hS
uYWT4rCOwVQaV/TBDj4T8diDxYpnAXvpO8U+WdqLddhUNaYeDym/HPq2cFsN9VdY
9FYiVl4ZAoGBAOWVsrRAWgFTmx99nUwy6XhobSWgZDrCQiSK50VGzblBdVnmMvyW
Q3LmdqtVQUkZLETx7PZXYkvIzMRP4oWGcViBPaSZ/IqX/kF5WJeXWW7Zgl5HEXTk
GaN26xl7yFjQ5l0f++HAwSW485B2GXvMcdp+6n7OfG6Xo1cg8CgWck5TAoGBAM+c
/h03pASGVvUDNNfeDulyxcXR/PZZTt1YMTqeYLmkbkJcIJVa2uTdDmzcEbGDA0eq
ezMDA+omGB+WR7HRe9+vgmz7Ww4BZRhKjvnxRgHlTGYHBsHhYr21fgPteGv/aDi2
xhAGqyOj1jua8ooqpw8TviYXk6ZbxMNF7eV9KxXbAoGAasEjKaHKuFcyCICWhfoe
ifi02AwuzwvJSci1JYd43a3MbZMXHlCY6HK1t5GbG+xyo1SDRUD42hhy7s3enQwY
5HikO0fHIILwnW1ZfpPH6D2H22LcgSgXq+T+CQl/7ZyloaPfsee5aFsKFqBz1RcJ
0fm1/GTzg1FLiJYuVdWqLTUCgYAaOURHwH1xLN7S9+K22Y+coSimAg4nt8QkZT1i
oBqrmD9tFmHvO5imi92Elo+NknTZmokROnJGIyWs57iKl2FEMdERnvYzYK26UcCZ
hYZIOwRZZs3Ns4BbYg9Ww6oQSiSJ9VwzLgRz7f/ja4DzPsv3NZExEo1N2A2UdMLF
1/eXPQKBgQDSCJ1tWQYVLvjrzJBC5gute7kHf1AhMoIEqpsEvk51JXu7+xN8BMnb
zSwIPR3fSngqLJqGw+Tz5LT3iSsDNVj7EnaHoYvTrxsd2yFYtVmz2fHgnHXBjZmj
AzDn4G6VZ+F11K/sdfuo+1vfgxPendYDkjp0ZtgJc97iBq49Devv1A==
-----END RSA PRIVATE KEY-----`

// Legacy v1/v2 ciphertexts (base64 string format) for backward compat tests.
var (
	// "test" encrypted with private key made up of 0x55 repeated (pre-existing mocked key)
	legacyCiphertext55_v1 = []byte("v1.QkJCQkJCQkJCQkJCQkJCQqXA0oAR9IDzFrICL6VB_9M")
	legacyCiphertext55_v2 = []byte("v2.QkJCQkJCQkJCQkJC9X30rkaY8XO5h_ujMLmLXiPzlYA")
)


func TestPool_Encrypt(t *testing.T) {
	block, _ := pem.Decode([]byte(dummyPrivKey))
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	t.Run("encrypts plaintext successfully with existing key", func(t *testing.T) {
		kms := &MockKMS{}
		remoteKey1 := &MockRemoteKey{}
		remoteKey2 := &MockRemoteKey{}
		keysTable := &MockKeysTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{
			{
				PoolSize:  10,
				Threshold: 2,
				RemoteKeys: map[string]encryption.RemoteKey{
					"remoteKey1": remoteKey1,
					"remoteKey2": remoteKey2,
				},
			},
		}

		att, err := enc.GetAttestation(context.Background(), nil, nil)
		require.NoError(t, err)
		defer func() {
			if err := att.Close(); err != nil {
				t.Log("failed to close attestation", err)
			}
		}()

		cipherKey, privateKey := newCipherKey(t, enc)

		shares, err := shamir.Split(privateKey, 2, 2)
		require.NoError(t, err)

		keysTable.On("Get", mock.Anything, 0, 4).Return(cipherKey, true, nil)
		remoteKey1.On("Decrypt", mock.Anything, att, "encryptedShare1").Return(shares[0], nil)
		remoteKey2.On("Decrypt", mock.Anything, att, "encryptedShare2").Return(shares[1], nil)

		pool := encryption.NewPool(enc, configs, keysTable, nil, nil)
		keyRef, ciphertext, err := pool.Encrypt(context.Background(), att, []byte("test"), []byte("aad"))
		require.NoError(t, err)
		require.Equal(t, "cipherKey4", keyRef)

		// v3 binary format: starts with 0x03
		require.NotEmpty(t, ciphertext)
		require.Equal(t, byte(0x03), ciphertext[0])

		// verify roundtrip: decrypt what we just encrypted
		keysTable.On("GetLatestByKeyRef", mock.Anything, "cipherKey4", false).Return(cipherKey, true, nil)
		plaintext, err := pool.Decrypt(context.Background(), att, keyRef, ciphertext, []byte("aad"))
		require.NoError(t, err)
		require.Equal(t, "test", string(plaintext))
	})

	t.Run("encrypts plaintext successfully with new key generation", func(t *testing.T) {
		kms := &MockKMS{}
		remoteKey1 := &MockRemoteKey{}
		remoteKey2 := &MockRemoteKey{}
		keysTable := &MockKeysTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{
			{
				PoolSize:  10,
				Threshold: 2,
				RemoteKeys: map[string]encryption.RemoteKey{
					"remoteKey1": remoteKey1,
					"remoteKey2": remoteKey2,
				},
			},
		}

		att, err := enc.GetAttestation(context.Background(), nil, nil)
		require.NoError(t, err)
		defer func() {
			if err := att.Close(); err != nil {
				t.Log("failed to close attestation", err)
			}
		}()

		keysTable.On("Get", mock.Anything, 0, 4).Return(nil, false, nil)
		remoteKey1.On("Encrypt", mock.Anything, att, mock.Anything).Return("encryptedShare1", nil)
		remoteKey2.On("Encrypt", mock.Anything, att, mock.Anything).Return("encryptedShare2", nil)

		createMatcher := func(key *data.CipherKey) bool {
			return key.Generation == 0 &&
				key.KeyIndex != nil &&
				*key.KeyIndex == 4 &&
				key.KeyRef == "QkJCQkJCQkJCQkJCQkJCQg" && // 0x42 repeated
				key.EncryptedShares["remoteKey1"] == "encryptedShare1" &&
				key.EncryptedShares["remoteKey2"] == "encryptedShare2"
		}
		keysTable.On("Create", mock.Anything, mock.MatchedBy(createMatcher)).Return(false, nil)

		pool := encryption.NewPool(enc, configs, keysTable, nil, nil)
		keyRef, ciphertext, err := pool.Encrypt(context.Background(), att, []byte("test"), []byte("aad"))
		require.NoError(t, err)
		require.Equal(t, "QkJCQkJCQkJCQkJCQkJCQg", keyRef)
		require.Equal(t, byte(0x03), ciphertext[0])
	})

	t.Run("handles key table get error", func(t *testing.T) {
		kms := &MockKMS{}
		remoteKey1 := &MockRemoteKey{}
		remoteKey2 := &MockRemoteKey{}
		keysTable := &MockKeysTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{
			{
				PoolSize:  10,
				Threshold: 2,
				RemoteKeys: map[string]encryption.RemoteKey{
					"remoteKey1": remoteKey1,
					"remoteKey2": remoteKey2,
				},
			},
		}

		att, err := enc.GetAttestation(context.Background(), nil, nil)
		require.NoError(t, err)
		defer func() {
			if err := att.Close(); err != nil {
				t.Log("failed to close attestation", err)
			}
		}()

		keysTable.On("Get", mock.Anything, 0, 4).Return(nil, false, errors.New("mock error"))

		pool := encryption.NewPool(enc, configs, keysTable, nil, nil)
		keyRef, ciphertext, err := pool.Encrypt(context.Background(), att, []byte("test"), []byte("aad"))
		require.Equal(t, "", keyRef)
		require.Nil(t, ciphertext)
		require.ErrorContains(t, err, "get key: mock error")
	})

	t.Run("handles key share encryption error", func(t *testing.T) {
		kms := &MockKMS{}
		remoteKey1 := &MockRemoteKey{}
		remoteKey2 := &MockRemoteKey{}
		keysTable := &MockKeysTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{
			{
				PoolSize:  10,
				Threshold: 2,
				RemoteKeys: map[string]encryption.RemoteKey{
					"remoteKey1": remoteKey1,
					"remoteKey2": remoteKey2,
				},
			},
		}

		att, err := enc.GetAttestation(context.Background(), nil, nil)
		require.NoError(t, err)
		defer func() {
			if err := att.Close(); err != nil {
				t.Log("failed to close attestation", err)
			}
		}()

		keysTable.On("Get", mock.Anything, 0, 4).Return(nil, false, nil)
		remoteKey1.On("Encrypt", mock.Anything, att, mock.Anything).Return("encryptedShare1", nil)
		remoteKey2.On("Encrypt", mock.Anything, att, mock.Anything).Return("", errors.New("mock error"))

		pool := encryption.NewPool(enc, configs, keysTable, nil, nil)
		keyRef, ciphertext, err := pool.Encrypt(context.Background(), att, []byte("test"), []byte("aad"))
		require.Equal(t, "", keyRef)
		require.Nil(t, ciphertext)
		require.ErrorContains(t, err, "generate key: encrypt share")
		require.ErrorContains(t, err, "mock error")
	})

	t.Run("handles key creation error", func(t *testing.T) {
		kms := &MockKMS{}
		remoteKey1 := &MockRemoteKey{}
		remoteKey2 := &MockRemoteKey{}
		keysTable := &MockKeysTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{
			{
				PoolSize:  10,
				Threshold: 2,
				RemoteKeys: map[string]encryption.RemoteKey{
					"remoteKey1": remoteKey1,
					"remoteKey2": remoteKey2,
				},
			},
		}

		att, err := enc.GetAttestation(context.Background(), nil, nil)
		require.NoError(t, err)
		defer func() {
			if err := att.Close(); err != nil {
				t.Log("failed to close attestation", err)
			}
		}()

		keysTable.On("Get", mock.Anything, 0, 4).Return(nil, false, nil)
		remoteKey1.On("Encrypt", mock.Anything, att, mock.Anything).Return("encryptedShare1", nil)
		remoteKey2.On("Encrypt", mock.Anything, att, mock.Anything).Return("encryptedShare2", nil)

		keysTable.On("Create", mock.Anything, mock.Anything).Return(false, errors.New("mock error"))

		pool := encryption.NewPool(enc, configs, keysTable, nil, nil)
		keyRef, ciphertext, err := pool.Encrypt(context.Background(), att, []byte("test"), []byte("aad"))
		require.Equal(t, "", keyRef)
		require.Nil(t, ciphertext)
		require.ErrorContains(t, err, "create key: mock error")
	})

	t.Run("handles concurrent key creation", func(t *testing.T) {
		kms := &MockKMS{}
		remoteKey1 := &MockRemoteKey{}
		remoteKey2 := &MockRemoteKey{}
		keysTable := &MockKeysTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{
			{
				PoolSize:  10,
				Threshold: 2,
				RemoteKeys: map[string]encryption.RemoteKey{
					"remoteKey1": remoteKey1,
					"remoteKey2": remoteKey2,
				},
			},
		}

		att, err := enc.GetAttestation(context.Background(), nil, nil)
		require.NoError(t, err)
		defer func() {
			if err := att.Close(); err != nil {
				t.Log("failed to close attestation", err)
			}
		}()

		cipherKey, privateKey := newCipherKey(t, enc)
		shares, err := shamir.Split(privateKey[:], 2, 2)
		require.NoError(t, err)

		keysTable.On("Get", mock.Anything, 0, 4).Return(nil, false, nil)
		remoteKey1.On("Encrypt", mock.Anything, att, mock.Anything).Return("encryptedShare1", nil)
		remoteKey2.On("Encrypt", mock.Anything, att, mock.Anything).Return("encryptedShare2", nil)

		keysTable.On("Create", mock.Anything, mock.Anything).Return(true, nil)
		keysTable.On("Get", mock.Anything, 0, 4).Return(cipherKey, true, nil)

		remoteKey1.On("Decrypt", mock.Anything, att, "encryptedShare1").Return(shares[0], nil)
		remoteKey2.On("Decrypt", mock.Anything, att, "encryptedShare2").Return(shares[1], nil)

		pool := encryption.NewPool(enc, configs, keysTable, nil, nil)
		keyRef, ciphertext, err := pool.Encrypt(context.Background(), att, []byte("test"), []byte("aad"))
		require.ErrorContains(t, err, "key already exists")
		require.Equal(t, "", keyRef)
		require.Nil(t, ciphertext)
	})
}

func TestPool_Decrypt(t *testing.T) {
	block, _ := pem.Decode([]byte(dummyPrivKey))
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	t.Run("decrypts v3 binary ciphertext", func(t *testing.T) {
		kms := &MockKMS{}
		remoteKey1 := &MockRemoteKey{}
		remoteKey2 := &MockRemoteKey{}
		keysTable := &MockKeysTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{
			{
				PoolSize:  10,
				Threshold: 2,
				RemoteKeys: map[string]encryption.RemoteKey{
					"remoteKey1": remoteKey1,
					"remoteKey2": remoteKey2,
				},
			},
		}

		att, err := enc.GetAttestation(context.Background(), nil, nil)
		require.NoError(t, err)
		defer func() {
			if err := att.Close(); err != nil {
				t.Log("failed to close attestation", err)
			}
		}()

		cipherKey, privateKey := newCipherKey(t, enc)
		shares, err := shamir.Split(privateKey, 2, 2)
		require.NoError(t, err)

		// Encrypt to get v3 ciphertext
		keysTable.On("Get", mock.Anything, 0, 4).Return(cipherKey, true, nil)
		remoteKey1.On("Decrypt", mock.Anything, att, "encryptedShare1").Return(shares[0], nil)
		remoteKey2.On("Decrypt", mock.Anything, att, "encryptedShare2").Return(shares[1], nil)

		pool := encryption.NewPool(enc, configs, keysTable, nil, nil)
		keyRef, ciphertext, err := pool.Encrypt(context.Background(), att, []byte("test"), []byte("aad"))
		require.NoError(t, err)

		// Decrypt the v3 ciphertext
		keysTable.On("GetLatestByKeyRef", mock.Anything, keyRef, false).Return(cipherKey, true, nil)
		plaintext, err := pool.Decrypt(context.Background(), att, keyRef, ciphertext, []byte("aad"))
		require.NoError(t, err)
		require.Equal(t, "test", string(plaintext))
	})

	t.Run("decrypts legacy v1 string ciphertext", func(t *testing.T) {
		kms := &MockKMS{}
		remoteKey1 := &MockRemoteKey{}
		remoteKey2 := &MockRemoteKey{}
		keysTable := &MockKeysTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{
			{
				PoolSize:  10,
				Threshold: 2,
				RemoteKeys: map[string]encryption.RemoteKey{
					"remoteKey1": remoteKey1,
					"remoteKey2": remoteKey2,
				},
			},
		}

		att, err := enc.GetAttestation(context.Background(), nil, nil)
		require.NoError(t, err)
		defer func() {
			if err := att.Close(); err != nil {
				t.Log("failed to close attestation", err)
			}
		}()

		cipherKey, privateKey := newCipherKey(t, enc)
		shares, err := shamir.Split(privateKey, 2, 2)
		require.NoError(t, err)

		keysTable.On("GetLatestByKeyRef", mock.Anything, "cipherKey4", false).Return(cipherKey, true, nil)
		remoteKey1.On("Decrypt", mock.Anything, att, "encryptedShare1").Return(shares[0], nil)
		remoteKey2.On("Decrypt", mock.Anything, att, "encryptedShare2").Return(shares[1], nil)

		pool := encryption.NewPool(enc, configs, keysTable, nil, nil)

		// v1 legacy ciphertext (AES-CBC, base64 string format)
		plaintext, err := pool.Decrypt(context.Background(), att, "cipherKey4", legacyCiphertext55_v1, nil)
		require.NoError(t, err)
		require.Equal(t, "test", string(plaintext))
	})

	t.Run("decrypts legacy v2 string ciphertext", func(t *testing.T) {
		kms := &MockKMS{}
		remoteKey1 := &MockRemoteKey{}
		remoteKey2 := &MockRemoteKey{}
		keysTable := &MockKeysTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{
			{
				PoolSize:  10,
				Threshold: 2,
				RemoteKeys: map[string]encryption.RemoteKey{
					"remoteKey1": remoteKey1,
					"remoteKey2": remoteKey2,
				},
			},
		}

		att, err := enc.GetAttestation(context.Background(), nil, nil)
		require.NoError(t, err)
		defer func() {
			if err := att.Close(); err != nil {
				t.Log("failed to close attestation", err)
			}
		}()

		cipherKey, privateKey := newCipherKey(t, enc)
		shares, err := shamir.Split(privateKey, 2, 2)
		require.NoError(t, err)

		keysTable.On("GetLatestByKeyRef", mock.Anything, "cipherKey4", false).Return(cipherKey, true, nil)
		remoteKey1.On("Decrypt", mock.Anything, att, "encryptedShare1").Return(shares[0], nil)
		remoteKey2.On("Decrypt", mock.Anything, att, "encryptedShare2").Return(shares[1], nil)

		pool := encryption.NewPool(enc, configs, keysTable, nil, nil)

		// v2 legacy ciphertext (AES-GCM, base64 string format)
		plaintext, err := pool.Decrypt(context.Background(), att, "cipherKey4", legacyCiphertext55_v2, []byte("aad"))
		require.NoError(t, err)
		require.Equal(t, "test", string(plaintext))
	})

	t.Run("decrypts successfully with 2/3 shares available", func(t *testing.T) {
		kms := &MockKMS{}
		remoteKey1 := &MockRemoteKey{}
		remoteKey2 := &MockRemoteKey{}
		remoteKey3 := &MockRemoteKey{}
		keysTable := &MockKeysTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{
			{
				PoolSize:  10,
				Threshold: 2,
				RemoteKeys: map[string]encryption.RemoteKey{
					"remoteKey1": remoteKey1,
					"remoteKey2": remoteKey2,
					"remoteKey3": remoteKey3,
				},
			},
		}

		att, err := enc.GetAttestation(context.Background(), nil, nil)
		require.NoError(t, err)
		defer func() {
			if err := att.Close(); err != nil {
				t.Log("failed to close attestation", err)
			}
		}()

		cipherKey, privateKey := newCipherKey(t, enc, func(key *data.CipherKey) {
			key.EncryptedShares["remoteKey3"] = "encryptedShare3"
		})

		shares, err := shamir.Split(privateKey, 3, 2)
		require.NoError(t, err)

		keysTable.On("GetLatestByKeyRef", mock.Anything, "cipherKey4", false).Return(cipherKey, true, nil)
		remoteKey1.On("Decrypt", mock.Anything, att, "encryptedShare1").Return(shares[0], nil)
		remoteKey2.On("Decrypt", mock.Anything, att, "encryptedShare2").Return(shares[1], nil)
		remoteKey3.On("Decrypt", mock.Anything, att, "encryptedShare3").Return(nil, errors.New("mock error"))

		pool := encryption.NewPool(enc, configs, keysTable, nil, nil)
		plaintext, err := pool.Decrypt(context.Background(), att, "cipherKey4", legacyCiphertext55_v2, []byte("aad"))
		require.NoError(t, err)
		require.Equal(t, "test", string(plaintext))
	})

	t.Run("handles insufficient shares", func(t *testing.T) {
		kms := &MockKMS{}
		remoteKey1 := &MockRemoteKey{}
		remoteKey2 := &MockRemoteKey{}
		remoteKey3 := &MockRemoteKey{}
		keysTable := &MockKeysTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{
			{
				PoolSize:  10,
				Threshold: 2,
				RemoteKeys: map[string]encryption.RemoteKey{
					"remoteKey1": remoteKey1,
					"remoteKey2": remoteKey2,
					"remoteKey3": remoteKey3,
				},
			},
		}

		att, err := enc.GetAttestation(context.Background(), nil, nil)
		require.NoError(t, err)
		defer func() {
			if err := att.Close(); err != nil {
				t.Log("failed to close attestation", err)
			}
		}()

		cipherKey, privateKey := newCipherKey(t, enc, func(key *data.CipherKey) {
			key.EncryptedShares["remoteKey3"] = "encryptedShare3"
		})

		shares, err := shamir.Split(privateKey, 3, 2)
		require.NoError(t, err)

		keysTable.On("GetLatestByKeyRef", mock.Anything, "cipherKey4", false).Return(cipherKey, true, nil)
		remoteKey1.On("Decrypt", mock.Anything, att, "encryptedShare1").Return(shares[0], nil)
		remoteKey2.On("Decrypt", mock.Anything, att, "encryptedShare2").Return(nil, errors.New("mock error"))
		remoteKey3.On("Decrypt", mock.Anything, att, "encryptedShare3").Return(nil, errors.New("mock error"))

		pool := encryption.NewPool(enc, configs, keysTable, nil, nil)
		plaintext, err := pool.Decrypt(context.Background(), att, "cipherKey4", legacyCiphertext55_v2, []byte("aad"))
		require.Empty(t, plaintext)
		require.ErrorContains(t, err, "combine shares: insufficient shares: need 2, got 1")
	})

	t.Run("decrypts successfully and migrates key", func(t *testing.T) {
		kms := &MockKMS{}
		remoteKey1 := &MockRemoteKey{}
		remoteKey2 := &MockRemoteKey{}
		remoteKey3 := &MockRemoteKey{}
		remoteKey4 := &MockRemoteKey{}
		keysTable := &MockKeysTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{
			{
				PoolSize:  10,
				Threshold: 2,
				RemoteKeys: map[string]encryption.RemoteKey{
					"remoteKey1": remoteKey1,
					"remoteKey2": remoteKey2,
				},
			},
			{
				PoolSize:  10,
				Threshold: 2,
				RemoteKeys: map[string]encryption.RemoteKey{
					"remoteKey3": remoteKey3,
					"remoteKey4": remoteKey4,
				},
			},
		}

		att, err := enc.GetAttestation(context.Background(), nil, nil)
		require.NoError(t, err)
		defer func() {
			if err := att.Close(); err != nil {
				t.Log("failed to close attestation", err)
			}
		}()

		cipherKey, privateKey := newCipherKey(t, enc)
		shares, err := shamir.Split(privateKey, 2, 2)
		require.NoError(t, err)

		keysTable.On("GetLatestByKeyRef", mock.Anything, "cipherKey4", false).Once().Return(cipherKey, true, nil)
		remoteKey1.On("Decrypt", mock.Anything, att, "encryptedShare1").Once().Return(shares[0], nil)
		remoteKey2.On("Decrypt", mock.Anything, att, "encryptedShare2").Once().Return(shares[1], nil)

		remoteKey3.On("Encrypt", mock.Anything, att, mock.Anything).Once().Return("encryptedShare3", nil)
		remoteKey4.On("Encrypt", mock.Anything, att, mock.Anything).Once().Return("encryptedShare4", nil)

		var migratedKey *data.CipherKey
		createMatcher := func(key *data.CipherKey) bool {
			return key.Generation == 1 &&
				key.KeyIndex == nil &&
				key.KeyRef == "cipherKey4" &&
				key.EncryptedShares["remoteKey3"] == "encryptedShare3" &&
				key.EncryptedShares["remoteKey4"] == "encryptedShare4" &&
				len(key.Attestation) > 0
		}
		keysTable.On("Create", mock.Anything, mock.MatchedBy(createMatcher)).Once().Return(false, nil).Run(func(args mock.Arguments) {
			migratedKey = args.Get(1).(*data.CipherKey)
		})

		pool := encryption.NewPool(enc, configs, keysTable, nil, nil)
		plaintext, err := pool.Decrypt(context.Background(), att, "cipherKey4", legacyCiphertext55_v2, []byte("aad"))
		require.NoError(t, err)
		require.Equal(t, "test", string(plaintext))

		// Decrypt again with the migrated key
		keysTable.On("GetLatestByKeyRef", mock.Anything, "cipherKey4", false).Once().Return(migratedKey, true, nil)
		remoteKey3.On("Decrypt", mock.Anything, att, "encryptedShare3").Once().Return(shares[0], nil)
		remoteKey4.On("Decrypt", mock.Anything, att, "encryptedShare4").Once().Return(shares[1], nil)

		plaintext, err = pool.Decrypt(context.Background(), att, "cipherKey4", legacyCiphertext55_v2, []byte("aad"))
		require.NoError(t, err)
		require.Equal(t, "test", string(plaintext))
	})

	t.Run("handles migration error gracefully", func(t *testing.T) {
		kms := &MockKMS{}
		remoteKey1 := &MockRemoteKey{}
		remoteKey2 := &MockRemoteKey{}
		remoteKey3 := &MockRemoteKey{}
		remoteKey4 := &MockRemoteKey{}
		keysTable := &MockKeysTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{
			{
				PoolSize:  10,
				Threshold: 2,
				RemoteKeys: map[string]encryption.RemoteKey{
					"remoteKey1": remoteKey1,
					"remoteKey2": remoteKey2,
				},
			},
			{
				PoolSize:  10,
				Threshold: 2,
				RemoteKeys: map[string]encryption.RemoteKey{
					"remoteKey3": remoteKey3,
					"remoteKey4": remoteKey4,
				},
			},
		}

		att, err := enc.GetAttestation(context.Background(), nil, nil)
		require.NoError(t, err)
		defer func() {
			if err := att.Close(); err != nil {
				t.Log("failed to close attestation", err)
			}
		}()

		cipherKey, privateKey := newCipherKey(t, enc)
		shares, err := shamir.Split(privateKey, 2, 2)
		require.NoError(t, err)

		keysTable.On("GetLatestByKeyRef", mock.Anything, "cipherKey4", false).Return(cipherKey, true, nil)
		remoteKey1.On("Decrypt", mock.Anything, att, "encryptedShare1").Return(shares[0], nil)
		remoteKey2.On("Decrypt", mock.Anything, att, "encryptedShare2").Return(shares[1], nil)

		remoteKey3.On("Encrypt", mock.Anything, att, mock.Anything).Return("encryptedShare3", nil)
		remoteKey4.On("Encrypt", mock.Anything, att, mock.Anything).Return("", errors.New("mock error"))

		pool := encryption.NewPool(enc, configs, keysTable, nil, nil)
		plaintext, err := pool.Decrypt(context.Background(), att, "cipherKey4", legacyCiphertext55_v2, []byte("aad"))
		require.NoError(t, err)
		require.Equal(t, "test", string(plaintext))
	})
}

func TestPool_RotateKey(t *testing.T) {
	block, _ := pem.Decode([]byte(dummyPrivKey))
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	t.Run("rotates key successfully", func(t *testing.T) {
		kms := &MockKMS{}
		keysTable := &MockKeysTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{{PoolSize: 10, Threshold: 2, RemoteKeys: map[string]encryption.RemoteKey{}}}

		att, err := enc.GetAttestation(context.Background(), nil, nil)
		require.NoError(t, err)
		defer func() { _ = att.Close() }()

		cipherKey, _ := newCipherKey(t, enc)

		// GetLatestByKeyRef with consistentRead=true
		keysTable.On("GetLatestByKeyRef", mock.Anything, "cipherKey4", true).Return(cipherKey, true, nil)
		keysTable.On("Deactivate", mock.Anything, "cipherKey4", 0, mock.AnythingOfType("time.Time"), mock.Anything).Return(nil)

		pool := encryption.NewPool(enc, configs, keysTable, nil, nil)
		err = pool.RotateKey(context.Background(), att, "cipherKey4")
		require.NoError(t, err)

		keysTable.AssertCalled(t, "GetLatestByKeyRef", mock.Anything, "cipherKey4", true)
		keysTable.AssertCalled(t, "Deactivate", mock.Anything, "cipherKey4", 0, mock.AnythingOfType("time.Time"), mock.Anything)
	})

	t.Run("key not found", func(t *testing.T) {
		kms := &MockKMS{}
		keysTable := &MockKeysTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{{PoolSize: 10, Threshold: 2, RemoteKeys: map[string]encryption.RemoteKey{}}}

		att, err := enc.GetAttestation(context.Background(), nil, nil)
		require.NoError(t, err)
		defer func() { _ = att.Close() }()

		keysTable.On("GetLatestByKeyRef", mock.Anything, "missing", true).Return(nil, false, nil)

		pool := encryption.NewPool(enc, configs, keysTable, nil, nil)
		err = pool.RotateKey(context.Background(), att, "missing")
		require.Error(t, err)
		require.ErrorContains(t, err, "cipher key not found")
	})

	t.Run("get key error", func(t *testing.T) {
		kms := &MockKMS{}
		keysTable := &MockKeysTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{{PoolSize: 10, Threshold: 2, RemoteKeys: map[string]encryption.RemoteKey{}}}

		att, err := enc.GetAttestation(context.Background(), nil, nil)
		require.NoError(t, err)
		defer func() { _ = att.Close() }()

		keysTable.On("GetLatestByKeyRef", mock.Anything, "cipherKey4", true).Return(nil, false, errors.New("db error"))

		pool := encryption.NewPool(enc, configs, keysTable, nil, nil)
		err = pool.RotateKey(context.Background(), att, "cipherKey4")
		require.Error(t, err)
		require.ErrorContains(t, err, "get cipher key: db error")
	})

	t.Run("deactivate error", func(t *testing.T) {
		kms := &MockKMS{}
		keysTable := &MockKeysTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{{PoolSize: 10, Threshold: 2, RemoteKeys: map[string]encryption.RemoteKey{}}}

		att, err := enc.GetAttestation(context.Background(), nil, nil)
		require.NoError(t, err)
		defer func() { _ = att.Close() }()

		cipherKey, _ := newCipherKey(t, enc)

		keysTable.On("GetLatestByKeyRef", mock.Anything, "cipherKey4", true).Return(cipherKey, true, nil)
		keysTable.On("Deactivate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("db write error"))

		pool := encryption.NewPool(enc, configs, keysTable, nil, nil)
		err = pool.RotateKey(context.Background(), att, "cipherKey4")
		require.Error(t, err)
		require.ErrorContains(t, err, "deactivate key: db write error")
	})
}

func TestPool_CleanupUnusedKeys(t *testing.T) {
	block, _ := pem.Decode([]byte(dummyPrivKey))
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	pastQuarantine := time.Now().Add(-48 * time.Hour)

	t.Run("deletes unused keys", func(t *testing.T) {
		kms := &MockKMS{}
		keysTable := &MockKeysTable{}
		dataTable := &MockEncryptedDataTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{{PoolSize: 10, Threshold: 2, RemoteKeys: map[string]encryption.RemoteKey{}}}

		inactiveKeys := []*data.CipherKey{
			{Generation: 0, KeyRef: "unused-key-1", InactiveSince: &pastQuarantine},
			{Generation: 0, KeyRef: "unused-key-2", InactiveSince: &pastQuarantine},
		}

		keysTable.On("ScanInactive", mock.Anything, (*string)(nil)).Return(inactiveKeys, nil, nil)
		dataTable.On("TableARN").Return("table-1")
		dataTable.On("ReferencesCipherKeyRef", mock.Anything, "unused-key-1").Return(false, nil)
		dataTable.On("ReferencesCipherKeyRef", mock.Anything, "unused-key-2").Return(false, nil)
		keysTable.On("Delete", mock.Anything, "unused-key-1", 0).Return(nil)
		keysTable.On("Delete", mock.Anything, "unused-key-2", 0).Return(nil)

		pool := encryption.NewPool(enc, configs, keysTable, []encryption.EncryptedDataTable{dataTable}, nil)
		deleted, err := pool.CleanupUnusedKeys(context.Background())
		require.NoError(t, err)
		require.Equal(t, 2, deleted)

		keysTable.AssertCalled(t, "Delete", mock.Anything, "unused-key-1", 0)
		keysTable.AssertCalled(t, "Delete", mock.Anything, "unused-key-2", 0)
	})

	t.Run("skips keys still in use", func(t *testing.T) {
		kms := &MockKMS{}
		keysTable := &MockKeysTable{}
		dataTable := &MockEncryptedDataTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{{PoolSize: 10, Threshold: 2, RemoteKeys: map[string]encryption.RemoteKey{}}}

		inactiveKeys := []*data.CipherKey{
			{Generation: 0, KeyRef: "used-key", InactiveSince: &pastQuarantine},
			{Generation: 0, KeyRef: "unused-key", InactiveSince: &pastQuarantine},
		}

		keysTable.On("ScanInactive", mock.Anything, (*string)(nil)).Return(inactiveKeys, nil, nil)
		dataTable.On("TableARN").Return("table-1")
		dataTable.On("ReferencesCipherKeyRef", mock.Anything, "used-key").Return(true, nil)
		dataTable.On("ReferencesCipherKeyRef", mock.Anything, "unused-key").Return(false, nil)
		keysTable.On("Delete", mock.Anything, "unused-key", 0).Return(nil)

		pool := encryption.NewPool(enc, configs, keysTable, []encryption.EncryptedDataTable{dataTable}, nil)
		deleted, err := pool.CleanupUnusedKeys(context.Background())
		require.NoError(t, err)
		require.Equal(t, 1, deleted)

		keysTable.AssertNotCalled(t, "Delete", mock.Anything, "used-key", mock.Anything)
		keysTable.AssertCalled(t, "Delete", mock.Anything, "unused-key", 0)
	})

	t.Run("checks all data tables", func(t *testing.T) {
		kms := &MockKMS{}
		keysTable := &MockKeysTable{}
		dataTable1 := &MockEncryptedDataTable{}
		dataTable2 := &MockEncryptedDataTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{{PoolSize: 10, Threshold: 2, RemoteKeys: map[string]encryption.RemoteKey{}}}

		inactiveKeys := []*data.CipherKey{
			{Generation: 0, KeyRef: "key-in-table2", InactiveSince: &pastQuarantine},
		}

		keysTable.On("ScanInactive", mock.Anything, (*string)(nil)).Return(inactiveKeys, nil, nil)
		dataTable1.On("TableARN").Return("table-1")
		dataTable2.On("TableARN").Return("table-2")
		// Not in table 1, but IS in table 2
		dataTable1.On("ReferencesCipherKeyRef", mock.Anything, "key-in-table2").Return(false, nil)
		dataTable2.On("ReferencesCipherKeyRef", mock.Anything, "key-in-table2").Return(true, nil)

		pool := encryption.NewPool(enc, configs, keysTable, []encryption.EncryptedDataTable{dataTable1, dataTable2}, nil)
		deleted, err := pool.CleanupUnusedKeys(context.Background())
		require.NoError(t, err)
		require.Equal(t, 0, deleted)

		keysTable.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("handles pagination", func(t *testing.T) {
		kms := &MockKMS{}
		keysTable := &MockKeysTable{}
		dataTable := &MockEncryptedDataTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{{PoolSize: 10, Threshold: 2, RemoteKeys: map[string]encryption.RemoteKey{}}}

		page1Keys := []*data.CipherKey{{Generation: 0, KeyRef: "key-page1", InactiveSince: &pastQuarantine}}
		page2Keys := []*data.CipherKey{{Generation: 0, KeyRef: "key-page2", InactiveSince: &pastQuarantine}}
		cursor := "cursor-1"

		keysTable.On("ScanInactive", mock.Anything, (*string)(nil)).Return(page1Keys, &cursor, nil)
		keysTable.On("ScanInactive", mock.Anything, &cursor).Return(page2Keys, nil, nil)
		dataTable.On("TableARN").Return("table-1")
		dataTable.On("ReferencesCipherKeyRef", mock.Anything, "key-page1").Return(false, nil)
		dataTable.On("ReferencesCipherKeyRef", mock.Anything, "key-page2").Return(false, nil)
		keysTable.On("Delete", mock.Anything, "key-page1", 0).Return(nil)
		keysTable.On("Delete", mock.Anything, "key-page2", 0).Return(nil)

		pool := encryption.NewPool(enc, configs, keysTable, []encryption.EncryptedDataTable{dataTable}, nil)
		deleted, err := pool.CleanupUnusedKeys(context.Background())
		require.NoError(t, err)
		require.Equal(t, 2, deleted)
	})

	t.Run("no inactive keys", func(t *testing.T) {
		kms := &MockKMS{}
		keysTable := &MockKeysTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{{PoolSize: 10, Threshold: 2, RemoteKeys: map[string]encryption.RemoteKey{}}}

		keysTable.On("ScanInactive", mock.Anything, (*string)(nil)).Return(nil, nil, nil)

		pool := encryption.NewPool(enc, configs, keysTable, nil, nil)
		deleted, err := pool.CleanupUnusedKeys(context.Background())
		require.NoError(t, err)
		require.Equal(t, 0, deleted)
	})

	t.Run("scan error", func(t *testing.T) {
		kms := &MockKMS{}
		keysTable := &MockKeysTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{{PoolSize: 10, Threshold: 2, RemoteKeys: map[string]encryption.RemoteKey{}}}

		keysTable.On("ScanInactive", mock.Anything, (*string)(nil)).Return(nil, nil, errors.New("scan failed"))

		pool := encryption.NewPool(enc, configs, keysTable, nil, nil)
		deleted, err := pool.CleanupUnusedKeys(context.Background())
		require.Error(t, err)
		require.ErrorContains(t, err, "list generation key refs: scan failed")
		require.Equal(t, 0, deleted)
	})

	t.Run("reference check error", func(t *testing.T) {
		kms := &MockKMS{}
		keysTable := &MockKeysTable{}
		dataTable := &MockEncryptedDataTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{{PoolSize: 10, Threshold: 2, RemoteKeys: map[string]encryption.RemoteKey{}}}

		inactiveKeys := []*data.CipherKey{{Generation: 0, KeyRef: "some-key", InactiveSince: &pastQuarantine}}

		keysTable.On("ScanInactive", mock.Anything, (*string)(nil)).Return(inactiveKeys, nil, nil)
		dataTable.On("TableARN").Return("table-1")
		dataTable.On("ReferencesCipherKeyRef", mock.Anything, "some-key").Return(false, errors.New("query failed"))

		pool := encryption.NewPool(enc, configs, keysTable, []encryption.EncryptedDataTable{dataTable}, nil)
		deleted, err := pool.CleanupUnusedKeys(context.Background())
		require.Error(t, err)
		require.ErrorContains(t, err, "count by key ref in table")
		require.ErrorContains(t, err, "query failed")
		require.Equal(t, 0, deleted)
	})

	t.Run("delete error", func(t *testing.T) {
		kms := &MockKMS{}
		keysTable := &MockKeysTable{}
		dataTable := &MockEncryptedDataTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{{PoolSize: 10, Threshold: 2, RemoteKeys: map[string]encryption.RemoteKey{}}}

		inactiveKeys := []*data.CipherKey{{Generation: 0, KeyRef: "some-key", InactiveSince: &pastQuarantine}}

		keysTable.On("ScanInactive", mock.Anything, (*string)(nil)).Return(inactiveKeys, nil, nil)
		dataTable.On("TableARN").Return("table-1")
		dataTable.On("ReferencesCipherKeyRef", mock.Anything, "some-key").Return(false, nil)
		keysTable.On("Delete", mock.Anything, "some-key", 0).Return(errors.New("delete failed"))

		pool := encryption.NewPool(enc, configs, keysTable, []encryption.EncryptedDataTable{dataTable}, nil)
		deleted, err := pool.CleanupUnusedKeys(context.Background())
		require.Error(t, err)
		require.ErrorContains(t, err, "delete cipher key by ref")
		require.ErrorContains(t, err, "delete failed")
		require.Equal(t, 0, deleted)
	})

	t.Run("skips keys still in quarantine", func(t *testing.T) {
		kms := &MockKMS{}
		keysTable := &MockKeysTable{}
		dataTable := &MockEncryptedDataTable{}

		random := &constantReader{value: 0x42}
		enc, err := enclave.New(context.Background(), enclave.DummyProvider(random), kms, privKey)
		require.NoError(t, err)

		configs := []*encryption.Config{{PoolSize: 10, Threshold: 2, RemoteKeys: map[string]encryption.RemoteKey{}}}

		recentlyRotated := time.Now().Add(-1 * time.Hour)
		inactiveKeys := []*data.CipherKey{
			{Generation: 0, KeyRef: "recent-key", InactiveSince: &recentlyRotated},
			{Generation: 0, KeyRef: "old-key", InactiveSince: &pastQuarantine},
		}

		keysTable.On("ScanInactive", mock.Anything, (*string)(nil)).Return(inactiveKeys, nil, nil)
		dataTable.On("TableARN").Return("table-1")
		dataTable.On("ReferencesCipherKeyRef", mock.Anything, "old-key").Return(false, nil)
		keysTable.On("Delete", mock.Anything, "old-key", 0).Return(nil)

		pool := encryption.NewPool(enc, configs, keysTable, []encryption.EncryptedDataTable{dataTable}, nil)
		deleted, err := pool.CleanupUnusedKeys(context.Background())
		require.NoError(t, err)
		require.Equal(t, 1, deleted)

		keysTable.AssertNotCalled(t, "Delete", mock.Anything, "recent-key", mock.Anything)
		keysTable.AssertCalled(t, "Delete", mock.Anything, "old-key", 0)
	})
}
