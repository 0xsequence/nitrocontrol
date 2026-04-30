package data_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/0xsequence/nitrocontrol/encryption/data"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stretchr/testify/require"
)

// --- CiphertextValue tests ---

func TestCiphertextValue(t *testing.T) {
	t.Run("MarshalDynamoDB", func(t *testing.T) {
		t.Run("writes as Binary attribute", func(t *testing.T) {
			cv := data.CiphertextValue([]byte("some-ciphertext"))
			av, err := cv.MarshalDynamoDBAttributeValue()
			require.NoError(t, err)

			bav, ok := av.(*types.AttributeValueMemberB)
			require.True(t, ok, "expected AttributeValueMemberB, got %T", av)
			require.Equal(t, []byte("some-ciphertext"), bav.Value)
		})

		t.Run("writes binary data", func(t *testing.T) {
			cv := data.CiphertextValue([]byte{0x03, 0xDE, 0xAD, 0xBE, 0xEF})
			av, err := cv.MarshalDynamoDBAttributeValue()
			require.NoError(t, err)

			bav, ok := av.(*types.AttributeValueMemberB)
			require.True(t, ok)
			require.Equal(t, []byte{0x03, 0xDE, 0xAD, 0xBE, 0xEF}, bav.Value)
		})

		t.Run("writes empty value", func(t *testing.T) {
			cv := data.CiphertextValue(nil)
			av, err := cv.MarshalDynamoDBAttributeValue()
			require.NoError(t, err)

			bav, ok := av.(*types.AttributeValueMemberB)
			require.True(t, ok)
			require.Nil(t, bav.Value)
		})

		t.Run("writes legacy string content as binary", func(t *testing.T) {
			cv := data.CiphertextValue([]byte("v2.QkJCQkJC"))
			av, err := cv.MarshalDynamoDBAttributeValue()
			require.NoError(t, err)

			bav, ok := av.(*types.AttributeValueMemberB)
			require.True(t, ok)
			require.Equal(t, []byte("v2.QkJCQkJC"), bav.Value)
		})
	})

	t.Run("UnmarshalDynamoDB", func(t *testing.T) {
		t.Run("reads from String attribute", func(t *testing.T) {
			var cv data.CiphertextValue
			err := cv.UnmarshalDynamoDBAttributeValue(&types.AttributeValueMemberS{
				Value: "v2.base64data",
			})
			require.NoError(t, err)
			require.Equal(t, data.CiphertextValue([]byte("v2.base64data")), cv)
		})

		t.Run("reads from Binary attribute", func(t *testing.T) {
			var cv data.CiphertextValue
			err := cv.UnmarshalDynamoDBAttributeValue(&types.AttributeValueMemberB{
				Value: []byte{0x03, 0xAA, 0xBB},
			})
			require.NoError(t, err)
			require.Equal(t, data.CiphertextValue([]byte{0x03, 0xAA, 0xBB}), cv)
		})

		t.Run("reads empty String", func(t *testing.T) {
			var cv data.CiphertextValue
			err := cv.UnmarshalDynamoDBAttributeValue(&types.AttributeValueMemberS{Value: ""})
			require.NoError(t, err)
			require.Equal(t, data.CiphertextValue([]byte("")), cv)
		})

		t.Run("reads empty Binary", func(t *testing.T) {
			var cv data.CiphertextValue
			err := cv.UnmarshalDynamoDBAttributeValue(&types.AttributeValueMemberB{Value: nil})
			require.NoError(t, err)
			require.Nil(t, []byte(cv))
		})

		t.Run("error on Number attribute", func(t *testing.T) {
			var cv data.CiphertextValue
			err := cv.UnmarshalDynamoDBAttributeValue(&types.AttributeValueMemberN{Value: "42"})
			require.Error(t, err)
			require.Contains(t, err.Error(), "unsupported attribute type")
		})

		t.Run("error on Bool attribute", func(t *testing.T) {
			var cv data.CiphertextValue
			err := cv.UnmarshalDynamoDBAttributeValue(&types.AttributeValueMemberBOOL{Value: true})
			require.Error(t, err)
			require.Contains(t, err.Error(), "unsupported attribute type")
		})

		t.Run("error on List attribute", func(t *testing.T) {
			var cv data.CiphertextValue
			err := cv.UnmarshalDynamoDBAttributeValue(&types.AttributeValueMemberL{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "unsupported attribute type")
		})

		t.Run("error on Map attribute", func(t *testing.T) {
			var cv data.CiphertextValue
			err := cv.UnmarshalDynamoDBAttributeValue(&types.AttributeValueMemberM{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "unsupported attribute type")
		})

		t.Run("large binary data roundtrip", func(t *testing.T) {
			original := make([]byte, 100*1024) // 100 KB
			for i := range original {
				original[i] = byte(i % 256)
			}

			cv := data.CiphertextValue(original)
			av, err := cv.MarshalDynamoDBAttributeValue()
			require.NoError(t, err)

			var cv2 data.CiphertextValue
			err = cv2.UnmarshalDynamoDBAttributeValue(av)
			require.NoError(t, err)
			require.Equal(t, cv, cv2)
		})
	})
}

// --- Mock encryptor/decryptor ---

type mockEncryptor struct {
	keyID      string
	ciphertext []byte
	err        error
}

func (m *mockEncryptor) Encrypt(_ context.Context, _ *enclave.Attestation, plaintext []byte, additionalData []byte) (string, []byte, error) {
	if m.err != nil {
		return "", nil, m.err
	}
	return m.keyID, append(m.ciphertext, plaintext...), nil
}

type mockDecryptor struct {
	plaintext []byte
	err       error
}

func (m *mockDecryptor) Decrypt(_ context.Context, _ *enclave.Attestation, keyID string, ciphertext []byte, additionalData []byte) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.plaintext, nil
}

// --- Test payload ---

type testPayload struct {
	Name  string `json:"name" cbor:"0,keyasint"`
	Value int    `json:"value" cbor:"1,keyasint"`
}

// --- Encrypt tests ---

func TestEncrypt(t *testing.T) {
	ctx := context.Background()

	t.Run("JSON", func(t *testing.T) {
		enc := &mockEncryptor{keyID: "key-1", ciphertext: nil}

		t.Run("struct", func(t *testing.T) {
			payload := &testPayload{Name: "test", Value: 42}
			result, err := data.Encrypt[*testPayload, data.JSONCodec](ctx, nil, enc, payload, "aad")
			require.NoError(t, err)

			require.Equal(t, "key-1", result.CipherKeyRef)
			require.NotEmpty(t, result.Ciphertext)
			require.NotEmpty(t, result.CiphertextHash)

			// Ciphertext should contain JSON (mock encryptor passes plaintext through)
			require.Contains(t, string(result.Ciphertext), `"name":"test"`)
			require.Contains(t, string(result.Ciphertext), `"value":42`)

			// Hash should be sha256 of ciphertext
			expectedHash := sha256.Sum256([]byte(result.Ciphertext))
			require.Equal(t, expectedHash[:], result.CiphertextHash)
		})

		t.Run("string", func(t *testing.T) {
			result, err := data.Encrypt[string, data.JSONCodec](ctx, nil, enc, "hello", "aad")
			require.NoError(t, err)
			require.Contains(t, string(result.Ciphertext), `"hello"`)
		})

		t.Run("nil pointer", func(t *testing.T) {
			result, err := data.Encrypt[*testPayload, data.JSONCodec](ctx, nil, enc, nil, "aad")
			require.NoError(t, err)
			require.Contains(t, string(result.Ciphertext), "null")
		})

		t.Run("encryptor error", func(t *testing.T) {
			failEnc := &mockEncryptor{err: errors.New("kms unavailable")}
			_, err := data.Encrypt[string, data.JSONCodec](ctx, nil, failEnc, "test", "aad")
			require.Error(t, err)
			require.ErrorContains(t, err, "kms unavailable")
		})

		t.Run("marshal error", func(t *testing.T) {
			_, err := data.Encrypt[chan int, data.JSONCodec](ctx, nil, enc, make(chan int), "aad")
			require.Error(t, err)
			require.ErrorContains(t, err, "marshal data")
		})

		t.Run("empty AAD", func(t *testing.T) {
			fields, err := data.EncryptJSON(ctx, nil, enc, "test", "")
			require.NoError(t, err)
			require.NotEmpty(t, fields.Ciphertext)
		})
	})

	t.Run("CBOR", func(t *testing.T) {
		enc := &mockEncryptor{keyID: "key-2", ciphertext: nil}

		t.Run("struct", func(t *testing.T) {
			payload := &testPayload{Name: "test", Value: 42}
			result, err := data.Encrypt[*testPayload, data.CBORCodec](ctx, nil, enc, payload, "aad")
			require.NoError(t, err)

			require.Equal(t, "key-2", result.CipherKeyRef)
			require.NotEmpty(t, result.Ciphertext)
			require.NotEmpty(t, result.CiphertextHash)

			// CBOR output should be different from JSON (binary format)
			require.NotContains(t, string(result.Ciphertext), `"name"`)
		})

		t.Run("string", func(t *testing.T) {
			result, err := data.Encrypt[string, data.CBORCodec](ctx, nil, enc, "hello", "aad")
			require.NoError(t, err)
			require.NotEmpty(t, result.Ciphertext)
		})
	})

	t.Run("EncryptJSON convenience", func(t *testing.T) {
		enc := &mockEncryptor{keyID: "key-json", ciphertext: nil}
		payload := &testPayload{Name: "convenience", Value: 99}
		result, err := data.EncryptJSON(ctx, nil, enc, payload, "aad")
		require.NoError(t, err)
		require.Equal(t, "key-json", result.CipherKeyRef)
		require.Contains(t, string(result.Ciphertext), `"name":"convenience"`)
	})

	t.Run("EncryptCBOR convenience", func(t *testing.T) {
		enc := &mockEncryptor{keyID: "key-cbor", ciphertext: nil}
		payload := &testPayload{Name: "convenience", Value: 99}
		result, err := data.EncryptCBOR(ctx, nil, enc, payload, "aad")
		require.NoError(t, err)
		require.Equal(t, "key-cbor", result.CipherKeyRef)
		require.NotContains(t, string(result.Ciphertext), `"name"`)
	})
}

// --- Decrypt tests ---

func TestDecrypt(t *testing.T) {
	ctx := context.Background()

	t.Run("JSON", func(t *testing.T) {
		t.Run("struct", func(t *testing.T) {
			dec := &mockDecryptor{plaintext: []byte(`{"name":"decrypted","value":7}`)}
			ed := data.EncryptedData[*testPayload, data.JSONCodec]{
				EncryptedFields: data.EncryptedFields{
					CipherKeyRef: "key-1",
					Ciphertext:   data.CiphertextValue([]byte("encrypted-data")),
				},
			}

			result, err := ed.Decrypt(ctx, nil, dec, "aad")
			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, "decrypted", result.Name)
			require.Equal(t, 7, result.Value)
		})

		t.Run("string", func(t *testing.T) {
			dec := &mockDecryptor{plaintext: []byte(`"hello world"`)}
			ed := data.EncryptedData[string, data.JSONCodec]{
				EncryptedFields: data.EncryptedFields{
					CipherKeyRef: "key-1",
					Ciphertext:   data.CiphertextValue([]byte("encrypted-data")),
				},
			}

			result, err := ed.Decrypt(ctx, nil, dec, "aad")
			require.NoError(t, err)
			require.Equal(t, "hello world", result)
		})

		t.Run("decryptor error", func(t *testing.T) {
			dec := &mockDecryptor{err: errors.New("decryption failed")}
			ed := data.EncryptedData[string, data.JSONCodec]{
				EncryptedFields: data.EncryptedFields{
					CipherKeyRef: "key-1",
					Ciphertext:   data.CiphertextValue([]byte("encrypted-data")),
				},
			}

			_, err := ed.Decrypt(ctx, nil, dec, "aad")
			require.Error(t, err)
			require.ErrorContains(t, err, "decryption failed")
		})

		t.Run("unmarshal error", func(t *testing.T) {
			dec := &mockDecryptor{plaintext: []byte("not-json")}
			ed := data.EncryptedData[*testPayload, data.JSONCodec]{
				EncryptedFields: data.EncryptedFields{
					CipherKeyRef: "key-1",
					Ciphertext:   data.CiphertextValue([]byte("encrypted-data")),
				},
			}

			_, err := ed.Decrypt(ctx, nil, dec, "aad")
			require.Error(t, err)
			require.ErrorContains(t, err, "unmarshal data")
		})

		t.Run("returns zero value on error", func(t *testing.T) {
			dec := &mockDecryptor{err: errors.New("fail")}
			ed := data.EncryptedData[*testPayload, data.JSONCodec]{
				EncryptedFields: data.EncryptedFields{
					CipherKeyRef: "key-1",
					Ciphertext:   data.CiphertextValue([]byte("encrypted-data")),
				},
			}

			result, err := ed.Decrypt(ctx, nil, dec, "aad")
			require.Error(t, err)
			require.Nil(t, result)
		})
	})

	t.Run("CBOR", func(t *testing.T) {
		t.Run("struct", func(t *testing.T) {
			var codec data.CBORCodec
			cborBytes, err := codec.Marshal(&testPayload{Name: "cbor-test", Value: 55})
			require.NoError(t, err)

			dec := &mockDecryptor{plaintext: cborBytes}
			ed := data.EncryptedData[*testPayload, data.CBORCodec]{
				EncryptedFields: data.EncryptedFields{
					CipherKeyRef: "key-1",
					Ciphertext:   data.CiphertextValue([]byte("encrypted-data")),
				},
			}

			result, err := ed.Decrypt(ctx, nil, dec, "aad")
			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, "cbor-test", result.Name)
			require.Equal(t, 55, result.Value)
		})

		t.Run("unmarshal error", func(t *testing.T) {
			dec := &mockDecryptor{plaintext: []byte("not-cbor!!!")}
			ed := data.EncryptedData[*testPayload, data.CBORCodec]{
				EncryptedFields: data.EncryptedFields{
					CipherKeyRef: "key-1",
					Ciphertext:   data.CiphertextValue([]byte("encrypted-data")),
				},
			}

			_, err := ed.Decrypt(ctx, nil, dec, "aad")
			require.Error(t, err)
			require.ErrorContains(t, err, "unmarshal data")
		})
	})
}

// --- Encrypt + Decrypt roundtrip ---

func TestEncryptDecrypt(t *testing.T) {
	ctx := context.Background()
	enc := &mockEncryptor{keyID: "key-rt", ciphertext: nil}

	t.Run("JSON roundtrip", func(t *testing.T) {
		payload := &testPayload{Name: "roundtrip", Value: 123}
		fields, err := data.EncryptJSON(ctx, nil, enc, payload, "aad")
		require.NoError(t, err)

		dec := &mockDecryptor{plaintext: []byte(fields.Ciphertext)}
		ed := data.EncryptedData[*testPayload, data.JSONCodec]{EncryptedFields: fields}
		result, err := ed.Decrypt(ctx, nil, dec, "aad")
		require.NoError(t, err)
		require.Equal(t, payload.Name, result.Name)
		require.Equal(t, payload.Value, result.Value)
	})

	t.Run("CBOR roundtrip", func(t *testing.T) {
		payload := &testPayload{Name: "roundtrip-cbor", Value: 456}
		fields, err := data.EncryptCBOR(ctx, nil, enc, payload, "aad")
		require.NoError(t, err)

		dec := &mockDecryptor{plaintext: []byte(fields.Ciphertext)}
		ed := data.EncryptedData[*testPayload, data.CBORCodec]{EncryptedFields: fields}
		result, err := ed.Decrypt(ctx, nil, dec, "aad")
		require.NoError(t, err)
		require.Equal(t, payload.Name, result.Name)
		require.Equal(t, payload.Value, result.Value)
	})

	t.Run("different types", func(t *testing.T) {
		t.Run("map", func(t *testing.T) {
			input := map[string]int{"a": 1, "b": 2}
			fields, err := data.EncryptJSON(ctx, nil, enc, input, "aad")
			require.NoError(t, err)

			dec := &mockDecryptor{plaintext: []byte(fields.Ciphertext)}
			ed := data.EncryptedData[map[string]int, data.JSONCodec]{EncryptedFields: fields}
			result, err := ed.Decrypt(ctx, nil, dec, "aad")
			require.NoError(t, err)
			require.Equal(t, input, result)
		})

		t.Run("slice", func(t *testing.T) {
			input := []string{"foo", "bar", "baz"}
			fields, err := data.EncryptJSON(ctx, nil, enc, input, "aad")
			require.NoError(t, err)

			dec := &mockDecryptor{plaintext: []byte(fields.Ciphertext)}
			ed := data.EncryptedData[[]string, data.JSONCodec]{EncryptedFields: fields}
			result, err := ed.Decrypt(ctx, nil, dec, "aad")
			require.NoError(t, err)
			require.Equal(t, input, result)
		})

		t.Run("int", func(t *testing.T) {
			input := 42
			fields, err := data.EncryptJSON(ctx, nil, enc, input, "aad")
			require.NoError(t, err)

			dec := &mockDecryptor{plaintext: []byte(fields.Ciphertext)}
			ed := data.EncryptedData[int, data.JSONCodec]{EncryptedFields: fields}
			result, err := ed.Decrypt(ctx, nil, dec, "aad")
			require.NoError(t, err)
			require.Equal(t, input, result)
		})
	})

	t.Run("codec mismatch fails", func(t *testing.T) {
		payload := &testPayload{Name: "mismatch", Value: 1}
		fields, err := data.EncryptJSON(ctx, nil, enc, payload, "aad")
		require.NoError(t, err)

		dec := &mockDecryptor{plaintext: []byte(fields.Ciphertext)}
		ed := data.EncryptedData[*testPayload, data.CBORCodec]{EncryptedFields: fields}
		_, err = ed.Decrypt(ctx, nil, dec, "aad")
		require.Error(t, err)
		require.ErrorContains(t, err, "unmarshal data")
	})

	t.Run("hash is sha256 of ciphertext", func(t *testing.T) {
		prefixEnc := &mockEncryptor{keyID: "key-hash", ciphertext: []byte("prefix-")}
		fields, err := data.EncryptJSON(ctx, nil, prefixEnc, "test", "aad")
		require.NoError(t, err)

		expectedHash := sha256.Sum256([]byte(fields.Ciphertext))
		require.Equal(t, expectedHash[:], fields.CiphertextHash)
	})
}

// --- Payload size comparison ---

type walletData struct {
	ID        string `json:"id" cbor:"0,keyasint"`
	Scope     string `json:"scope" cbor:"1,keyasint"`
	Status    string `json:"status" cbor:"2,keyasint"`
	Type      string `json:"type" cbor:"3,keyasint"`
	Address   string `json:"address" cbor:"4,keyasint"`
	KeyOrigin string `json:"keyOrigin" cbor:"5,keyasint"`
	Reference string `json:"reference" cbor:"6,keyasint"`
}

type credentialData struct {
	Scope    string   `json:"scope" cbor:"0,keyasint"`
	AuthMode string   `json:"authMode" cbor:"1,keyasint"`
	Identity identity `json:"identity" cbor:"2,keyasint"`
	Extras   []string `json:"extras" cbor:"3,keyasint"`
}

type identity struct {
	Type    string `json:"type" cbor:"0,keyasint"`
	Issuer  string `json:"issuer" cbor:"1,keyasint"`
	Subject string `json:"subject" cbor:"2,keyasint"`
	Email   string `json:"email" cbor:"3,keyasint"`
}

var (
	smallPayload = &walletData{
		ID:        "wallet-abc123",
		Scope:     "@1",
		Status:    "active",
		Type:      "eoa",
		Address:   "0x1234567890abcdef1234567890abcdef12345678",
		KeyOrigin: "generated",
		Reference: "ref-001",
	}

	largePayload = &credentialData{
		Scope:    "@1:production",
		AuthMode: "IDToken",
		Identity: identity{
			Type:    "OIDC",
			Issuer:  "https://accounts.google.com",
			Subject: "1234567890abcdef1234567890abcdef",
			Email:   "user@example.com",
		},
		Extras: []string{
			"extra-field-1-with-some-realistic-length-data",
			"extra-field-2-with-some-realistic-length-data",
			"extra-field-3-with-some-realistic-length-data",
		},
	}
)

func TestCodecPayloadSize(t *testing.T) {
	var jsonCodec data.JSONCodec
	var cborCodec data.CBORCodec

	for _, tt := range []struct {
		name    string
		payload any
	}{
		{"small", smallPayload},
		{"large", largePayload},
	} {
		t.Run(tt.name, func(t *testing.T) {
			jsonBytes, err := jsonCodec.Marshal(tt.payload)
			require.NoError(t, err)
			cborBytes, err := cborCodec.Marshal(tt.payload)
			require.NoError(t, err)

			t.Logf("JSON=%d bytes, CBOR=%d bytes (%.0f%% of JSON)",
				len(jsonBytes), len(cborBytes), float64(len(cborBytes))/float64(len(jsonBytes))*100)
			require.Less(t, len(cborBytes), len(jsonBytes))
		})
	}

	t.Run("roundtrip preserves data", func(t *testing.T) {
		for _, codec := range []data.Codec{jsonCodec, cborCodec} {
			b, err := codec.Marshal(smallPayload)
			require.NoError(t, err)
			var result walletData
			require.NoError(t, codec.Unmarshal(b, &result))
			require.Equal(t, *smallPayload, result)
		}
	})
}

// --- Benchmarks ---

func BenchmarkCodec_Marshal(b *testing.B) {
	b.Run("JSON/small", func(b *testing.B) {
		var codec data.JSONCodec
		b.ResetTimer()
		for b.Loop() {
			_, _ = codec.Marshal(smallPayload)
		}
	})

	b.Run("CBOR/small", func(b *testing.B) {
		var codec data.CBORCodec
		b.ResetTimer()
		for b.Loop() {
			_, _ = codec.Marshal(smallPayload)
		}
	})

	b.Run("JSON/large", func(b *testing.B) {
		var codec data.JSONCodec
		b.ResetTimer()
		for b.Loop() {
			_, _ = codec.Marshal(largePayload)
		}
	})

	b.Run("CBOR/large", func(b *testing.B) {
		var codec data.CBORCodec
		b.ResetTimer()
		for b.Loop() {
			_, _ = codec.Marshal(largePayload)
		}
	})
}

func BenchmarkCodec_Unmarshal(b *testing.B) {
	var jsonCodec data.JSONCodec
	var cborCodec data.CBORCodec

	jsonSmall, _ := jsonCodec.Marshal(smallPayload)
	cborSmall, _ := cborCodec.Marshal(smallPayload)
	jsonLarge, _ := jsonCodec.Marshal(largePayload)
	cborLarge, _ := cborCodec.Marshal(largePayload)

	b.Run("JSON/small", func(b *testing.B) {
		b.ResetTimer()
		for b.Loop() {
			var out walletData
			_ = jsonCodec.Unmarshal(jsonSmall, &out)
		}
	})

	b.Run("CBOR/small", func(b *testing.B) {
		b.ResetTimer()
		for b.Loop() {
			var out walletData
			_ = cborCodec.Unmarshal(cborSmall, &out)
		}
	})

	b.Run("JSON/large", func(b *testing.B) {
		b.ResetTimer()
		for b.Loop() {
			var out credentialData
			_ = jsonCodec.Unmarshal(jsonLarge, &out)
		}
	})

	b.Run("CBOR/large", func(b *testing.B) {
		b.ResetTimer()
		for b.Loop() {
			var out credentialData
			_ = cborCodec.Unmarshal(cborLarge, &out)
		}
	})
}

func BenchmarkEncryptDecrypt_Roundtrip(b *testing.B) {
	ctx := context.Background()
	enc := &mockEncryptor{keyID: "key-bench", ciphertext: nil}

	b.Run("JSON/small", func(b *testing.B) {
		b.ResetTimer()
		for b.Loop() {
			fields, _ := data.EncryptJSON(ctx, nil, enc, smallPayload, "aad")
			dec := &mockDecryptor{plaintext: []byte(fields.Ciphertext)}
			ed := data.EncryptedData[*walletData, data.JSONCodec]{EncryptedFields: fields}
			_, _ = ed.Decrypt(ctx, nil, dec, "aad")
		}
	})

	b.Run("CBOR/small", func(b *testing.B) {
		b.ResetTimer()
		for b.Loop() {
			fields, _ := data.EncryptCBOR(ctx, nil, enc, smallPayload, "aad")
			dec := &mockDecryptor{plaintext: []byte(fields.Ciphertext)}
			ed := data.EncryptedData[*walletData, data.CBORCodec]{EncryptedFields: fields}
			_, _ = ed.Decrypt(ctx, nil, dec, "aad")
		}
	})

	b.Run("JSON/large", func(b *testing.B) {
		b.ResetTimer()
		for b.Loop() {
			fields, _ := data.EncryptJSON(ctx, nil, enc, largePayload, "aad")
			dec := &mockDecryptor{plaintext: []byte(fields.Ciphertext)}
			ed := data.EncryptedData[*credentialData, data.JSONCodec]{EncryptedFields: fields}
			_, _ = ed.Decrypt(ctx, nil, dec, "aad")
		}
	})

	b.Run("CBOR/large", func(b *testing.B) {
		b.ResetTimer()
		for b.Loop() {
			fields, _ := data.EncryptCBOR(ctx, nil, enc, largePayload, "aad")
			dec := &mockDecryptor{plaintext: []byte(fields.Ciphertext)}
			ed := data.EncryptedData[*credentialData, data.CBORCodec]{EncryptedFields: fields}
			_, _ = ed.Decrypt(ctx, nil, dec, "aad")
		}
	})
}
