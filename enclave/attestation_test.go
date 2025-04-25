package enclave_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"sync"
	"testing"

	"github.com/0xsequence/tee-verifier/nitro"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/0xsequence/nitrocontrol/enclave"
)

var (
	testPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwg8xlWTIwm44aLEqiA5lweHUSm2eeKwrTg3qEUhOVyGAo3eN
XRoD9wOHzjcvS8r/qfQdSdLA9p6IbSxV9LU2fXgYnT3IDhNuQ1rVkiIYqWqPWUn2
izUMJmbdVFRsgWi7/keXkslZD0DeKQM1R2QsCRZnPGHU3Jo/+2b6dTg8IRoBH2cq
rAPuynqBXYCC9+wNdYMQLA5vdaVzhFBASIVkMDDWlMaFgdOsISMHy9Klm0cXj3RE
02VsHcOQ1NRLY4Ddgpb5r0LUB0nfB4HMeK9plYqkkVF5BJihoGtGmebGuMqSFNgU
XflrxH152bHAZqqV+aIPIy2y4IdaQgP1VJrVKwIDAQABAoIBAQCQhtJNyh6+t2np
hrD/XYGpkPATcmqIwukJm9FMh8ZYnAn7NKmiwiJb0FRPX8gosYoRYE6D0aOGyPEg
Jdnqgx+O+GeUjBO3b/85yKewyxYE7ujN/gjRCnP/EbMbADlDc+Y27cjUOILMmmoa
r1n5zoABUJ8YWGA43+Rw7vPvYy9dEn1fbmsp850u/Grqdi0MUwIpQe9VKkVsYZ0n
HKAz+uY9Mhb/CsveD75cHrpaa5Ilfjkzo47Gah/+E6LB3/5wRjlzNzLMAQT449PW
yt2E/DYtVAR8uAtbfHB3cFcgNrWVg9IwU1G74SwqqwgQfpfEqKqsqG9BBXz0vwLT
o3vczVWZAoGBANJbz5+1XRlblmDV8MnVGoaHoylIA6+xE5iTiAUtopxfh3lMgTAh
sIepf7na0nkNPXFrR48Tkm29Y4f8EU2LY0a1t9WyAyufz9UTA4ABlHCuKztSqpG7
SgGEQvr/bAE61uN7JwVXGUICAR27OVfy7+iIOCzFDaOwhyfrE2XuP82VAoGBAOwq
DYedgoxuV63BWYDtvUt4olQbBCczJKyDirTGGdiPyQbsfE5eegcfZYxRkiCJ0Z5z
9OQlafIrok93kwkWgta2dj3onbXKLUviyGMSW1kGXoaTZu47rTZ7nxhqS5QeySGl
sHs/8j3+2UPHnwvLMlrMAOhIFQYrlFeQkxvIw+e/AoGAZh2Xjon2JccmGuAAQZon
hEL326RP1cv6HUkQ8KKUm6BsHWAcHodcMJ8Bl/E31vesahCP7k6r+IXFeU/N/ny5
tqukECKYE2dC9saCHnOl4YVLC0M39gKbDF1uPnYbsgUkJ82yxY7gfgCHFi26yozu
FU17J5CI7HtXQPOGuSaM5nkCgYEAqI4PIAbMYVxz2cDRF9MWsuIDwdGSckPvXe14
tzNYyRc+nGF3CxwlLiY7fR3PFMgow1XxqFAHwN9htiQa3nahpYuO8vqubUxCbhIL
gaJdbjm8h4J3CXuwUd2DnJJpJOugFBLE1gK664KUIOs92dYKN4G4+BBSaRf7hU/b
nw34vNMCgYBfG/VbQXT1WCcJgVycnU1hX7zmyzB/hk0xkmLR0nUzTgXMKOKUUXgX
2mD7U5VGZPYj7t8P+bz6/HEZqKmOoxFkXpsMPug34ZUWfjv3uCm7CFHtxA+BDT+5
cJEGAbCDYhyjvtjBLNy7YDQ1hdmCnqMxg/5AIwUMkvTTRg+qepfboA==
-----END RSA PRIVATE KEY-----`

	// base64-encoded content of CiphertextForRecipient
	testCiphertextString = `MIAGCSqGSIb3DQEHA6CAMIACAQIxggFrMIIBZwIBAoAgljGgxlmRCtWqvB/s/Aw+ZNTDlc6Uka86SLVmlNmFGAMwPAYJKoZIhvcNAQEHMC+gDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEFAASCAQAXmjTiHpg+OcYaf2ISaDNpQcEOq61Sm3re3v+5z2hZPe8eoUGhmMS6pCuC+BRW7RpkjwDaXQzzR/jExnraEET3lj9oyAMMwKIahhHHIZ33qOTq1c/9NtMVZmm/j4UfyCpP8WMAFb2hvwIJbjnAGO9Xbw+NzWaQdvEyNDGUX+bPIuSDc75jjGH5KtdFLopk5k6nsTdU26qLkVE6Mg9Y//s0OJCvmYFgfw15IXDb50xJupWxCwbqGXWmfTBEo9M9AhelVbOXkitZR7hbnT6BZnsfpS2acZRNL4XxC+gg4Ml9fOiYsGWqSK8Lkwlp22rtL70CIHnggbb+oIE4ObR4TV8qMIAGCSqGSIb3DQEHATAdBglghkgBZQMEASoEEEMr/6uiZK+CzgfJvr61JTGggAQwfp0W0Q/QPYmg6AoC3DkE5+beNswVOX9ct5IIgIsvaAhTF9IiHdbX7yLa8YS2WQ/FAAAAAAAAAAAAAA==`

	expectedPlaintext = []byte{
		0x3b, 0xe8, 0x2c, 0x44, 0xf, 0x6, 0xcb, 0x4d,
		0x44, 0xc4, 0xc2, 0xec, 0x3b, 0xf3, 0xd, 0x47,
		0x24, 0x7, 0xd3, 0xa9, 0x12, 0x5a, 0xa4, 0xc1,
		0x84, 0x2b, 0x98, 0xf6, 0xbd, 0xd2, 0x6e, 0x41,
	}
)

func TestNitroAttestation_Decrypt(t *testing.T) {
	block, _ := pem.Decode([]byte(testPrivateKey))
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)
	ciphertextForRecipient, err := base64.StdEncoding.DecodeString(testCiphertextString)
	require.NoError(t, err)

	kmsMock := &mockKMS{
		decrypt: func(params *kms.DecryptInput) (*kms.DecryptOutput, error) {
			assert.Equal(t, []byte("ciphertext"), params.CiphertextBlob)
			assert.Equal(t, types.EncryptionAlgorithmSpecSymmetricDefault, params.EncryptionAlgorithm)
			require.NotNil(t, params.Recipient)
			doc, err := nitro.Parse(params.Recipient.AttestationDocument)
			require.NoError(t, err)
			assert.Equal(t, []byte("nonce"), doc.Nonce)
			assert.NoError(t, doc.Validate(nitro.WithRootFingerprint("14e8bc5fabb52876f35f122289eaabfa08885837cc7f161149c6d242596258aa")))
			assert.NoError(t, doc.Verify())
			assert.Equal(t, types.KeyEncryptionMechanismRsaesOaepSha256, params.Recipient.KeyEncryptionAlgorithm)
			return &kms.DecryptOutput{CiphertextForRecipient: ciphertextForRecipient}, nil
		},
	}

	e, err := enclave.New(context.Background(), enclave.DummyProvider, kmsMock, privKey)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			att, err := e.GetAttestation(context.Background(), []byte("nonce"), []byte("user-data"))
			require.NoError(t, err)

			plaintext, err := att.Decrypt(context.Background(), []byte("ciphertext"), nil)
			require.NoError(t, err)
			assert.Equal(t, expectedPlaintext, plaintext)
		}()
	}
	wg.Wait()
}

func TestAttestation_GenerateDataKey(t *testing.T) {
	block, _ := pem.Decode([]byte(testPrivateKey))
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)
	ciphertextForRecipient, err := base64.StdEncoding.DecodeString(testCiphertextString)
	require.NoError(t, err)

	kmsMock := &mockKMS{
		generateDataKey: func(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {
			require.NotNil(t, params.KeyId)
			require.NotNil(t, params.Recipient)
			assert.Equal(t, "key-id", *params.KeyId)
			assert.Equal(t, types.DataKeySpecAes256, params.KeySpec)
			doc, err := nitro.Parse(params.Recipient.AttestationDocument)
			require.NoError(t, err)
			assert.Equal(t, []byte("nonce"), doc.Nonce)
			assert.NoError(t, doc.Validate(nitro.WithRootFingerprint("14e8bc5fabb52876f35f122289eaabfa08885837cc7f161149c6d242596258aa")))
			assert.NoError(t, doc.Verify())
			assert.Equal(t, types.KeyEncryptionMechanismRsaesOaepSha256, params.Recipient.KeyEncryptionAlgorithm)
			return &kms.GenerateDataKeyOutput{
				CiphertextBlob:         []byte("ciphertext"),
				CiphertextForRecipient: ciphertextForRecipient,
			}, nil
		},
	}

	e, err := enclave.New(context.Background(), enclave.DummyProvider, kmsMock, privKey)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			att, err := e.GetAttestation(context.Background(), []byte("nonce"), []byte("user-data"))
			require.NoError(t, err)

			dk, err := att.GenerateDataKey(context.Background(), "key-id")
			require.NoError(t, err)
			assert.Equal(t, expectedPlaintext, dk.Plaintext)
			assert.Equal(t, []byte("ciphertext"), dk.Ciphertext)
		}()
	}
	wg.Wait()
}

type mockKMS struct {
	decrypt         func(params *kms.DecryptInput) (*kms.DecryptOutput, error)
	generateDataKey func(params *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error)
}

func (m *mockKMS) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	return m.decrypt(params)
}

func (m *mockKMS) GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	return m.generateDataKey(params)
}
