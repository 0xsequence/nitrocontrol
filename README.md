# nitrocontrol

Go library for building services inside [AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/). Provides cryptographic primitives, KMS-backed encryption with Shamir secret sharing, attestation middleware, and distributed tracing.

## Packages

### Core

| Package | Description |
|---|---|
| [`enclave`](./enclave/) | Nitro Security Module (NSM) session management, attestation documents, KMS key operations |
| [`attestation`](./attestation/) | HTTP middleware that injects NSM attestation into request context |
| [`tracing`](./tracing/) | Span-based distributed tracing with HTTP middleware and client instrumentation |

### Cryptography

| Package | Description |
|---|---|
| [`aesgcm`](./aesgcm/) | AES-256-GCM authenticated encryption with associated data |
| [`aescbc`](./aescbc/) | AES-256-CBC encryption with PKCS7 padding |
| [`cms`](./cms/) | CMS (RFC 5652) enveloped data parsing and decryption for KMS responses |

### Encryption Pool

| Package | Description |
|---|---|
| [`encryption`](./encryption/) | Key pool with Shamir secret sharing, key rotation, generation migration |
| [`encryption/data`](./encryption/data/) | Generic encrypted data storage for DynamoDB with codec support (JSON, CBOR) |
| [`encryption/kms`](./encryption/kms/) | AWS KMS `RemoteKey` implementation for encrypting Shamir shares |
| [`encryption/shamir`](./encryption/shamir/) | Shamir's Secret Sharing over GF(2^8) |

### Tools

| Package | Description |
|---|---|
| [`cmd/tracegen`](./cmd/tracegen/) | Code generator that wraps interfaces with tracing instrumentation |

## Usage

### Enclave setup

```go
import (
    "github.com/0xsequence/nitrocontrol/enclave"
    "github.com/aws/aws-sdk-go-v2/service/kms"
)

kmsClient := kms.NewFromConfig(awsCfg)

// Use NitroProvider in production, DummyProvider for local development
enc, err := enclave.New(ctx, enclave.NitroProvider, kmsClient)

att, err := enc.GetAttestation(ctx, nonce, userData)
defer att.Close()

dataKey, err := att.GenerateDataKey(ctx, kmsKeyARN)
```

### Encryption pool

The encryption pool manages a set of cipher keys split via Shamir secret sharing across multiple KMS keys. This provides key redundancy — any `threshold` of `n` KMS keys can reconstruct the cipher key.

```go
import (
    "github.com/0xsequence/nitrocontrol/encryption"
    encryptionkms "github.com/0xsequence/nitrocontrol/encryption/kms"
    "github.com/0xsequence/nitrocontrol/encryption/data"
)

// Configure remote KMS keys for Shamir share encryption
remoteKeys := []encryption.RemoteKey{
    encryptionkms.NewRemoteKey("arn:aws:kms:us-east-1:123:key/aaa"),
    encryptionkms.NewRemoteKey("arn:aws:kms:us-east-1:123:key/bbb"),
}
config := encryption.NewConfig(poolSize, threshold, remoteKeys)

// Create pool with cipher key table and data tables
pool := encryption.NewPool(enc, []*encryption.Config{config}, keysTable, dataTables, logger)

// Pool implements data.Encryptor and data.Decryptor
keyRef, ciphertext, err := pool.Encrypt(ctx, att, plaintext, aad)
plaintext, err := pool.Decrypt(ctx, att, keyRef, ciphertext, aad)
```

### Encrypted data with codecs

Type-safe encryption for DynamoDB records with pluggable serialization (JSON or CBOR):

```go
import "github.com/0xsequence/nitrocontrol/encryption/data"

// Encrypt with JSON
fields, err := data.EncryptJSON(ctx, att, pool, myStruct, "associated-data")

// Encrypt with CBOR (smaller payloads, faster serialization)
fields, err := data.EncryptCBOR(ctx, att, pool, myStruct, "associated-data")

// Decrypt — codec is determined by the type parameter
ed := data.EncryptedData[*MyStruct, data.CBORCodec]{EncryptedFields: fields}
result, err := ed.Decrypt(ctx, att, pool, "associated-data")
```

### Attestation middleware

```go
import "github.com/0xsequence/nitrocontrol/attestation"

r := chi.NewRouter()
r.Use(attestation.Middleware(enc, errorFn, loggerFn))

// In handlers:
att := attestation.FromContext(r.Context())
```

### Tracing

```go
import "github.com/0xsequence/nitrocontrol/tracing"

r.Use(tracing.Middleware(errorFn))

// In application code:
ctx, span := tracing.Trace(ctx, "operation.Name")
defer func() {
    span.RecordError(err)
    span.End()
}()

// Wrap HTTP clients for automatic span propagation
client := tracing.WrapClient(httpClient)
```

### Code generation

Generate traced wrappers for interfaces:

```go
//go:generate go run github.com/0xsequence/nitrocontrol/cmd/tracegen -interface=MyService
```

## Development

```bash
make build    # Build all packages
make test     # Run tests
make lint     # Run go vet + golangci-lint
make clean    # Clear test cache
```
