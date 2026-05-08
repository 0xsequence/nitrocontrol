package encryption

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	"github.com/0xsequence/nitrocontrol/aescbc"
	"github.com/0xsequence/nitrocontrol/aesgcm"
	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/0xsequence/nitrocontrol/encryption/data"
	"github.com/0xsequence/nitrocontrol/encryption/shamir"
	"github.com/0xsequence/nitrocontrol/tracing"
	"github.com/0xsequence/tee-verifier/nitro"
)

type KeysTable interface {
	Get(ctx context.Context, generation int, keyIndex int) (*data.CipherKey, bool, error)
	GetLatestByKeyRef(ctx context.Context, keyRef string, consistentRead bool) (*data.CipherKey, bool, error)
	ScanInactive(ctx context.Context, cursor *string) ([]*data.CipherKey, *string, error)
	Create(ctx context.Context, key *data.CipherKey) (bool, error)
	Delete(ctx context.Context, keyRef string, generation int) error
	Deactivate(ctx context.Context, keyRef string, generation int, now time.Time, attestation []byte) error
}

type EncryptedDataTable interface {
	TableARN() string
	ReferencesCipherKeyRef(ctx context.Context, keyRef string) (bool, error)
}

type Attester interface {
	GetAttestation(ctx context.Context, nonce []byte, userData []byte) (*enclave.Attestation, error)
}

type Pool struct {
	attester   Attester
	configs    []*Config
	keysTable  KeysTable
	dataTables []EncryptedDataTable
	logger     *slog.Logger
	cache      *dekCache // nil when caching disabled
}

// PoolOption configures optional Pool behavior.
type PoolOption func(*Pool)

// WithCache enables an in-memory LRU cache for decrypted data encryption keys,
// eliminating KMS round-trips on cache hits. The cache is local to this process
// and zeroes key material on eviction.
func WithCache(cfg CacheConfig) PoolOption {
	return func(p *Pool) {
		if cfg.MaxSize > 0 && cfg.TTL > 0 {
			p.cache = newDEKCache(cfg.MaxSize, cfg.TTL)
		}
	}
}

func NewPool(attester Attester, configs []*Config, keysTable KeysTable, dataTables []EncryptedDataTable, logger *slog.Logger, opts ...PoolOption) *Pool {
	if logger == nil {
		logger = slog.Default()
	}
	p := &Pool{
		attester:   attester,
		configs:    configs,
		keysTable:  keysTable,
		dataTables: dataTables,
		logger:     logger,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Encrypt encrypts the plaintext using a randomly selected cipher key from the Pool. It returns the key reference
// and the ciphertext.
//
// If the cipher key does not exist, it will be generated using the Pool's current generation config
// and stored in the keys table.
func (p *Pool) Encrypt(ctx context.Context, att *enclave.Attestation, plaintext []byte, additionalData []byte) (keyRef string, ciphertext []byte, err error) {
	ctx, span := tracing.Trace(ctx, "encryption.Pool.Encrypt")
	defer func() {
		span.RecordError(err)
		span.End()
	}()

	generation, config := p.currentConfig()
	span.SetAnnotation("generation", strconv.Itoa(generation))

	keyIndex, err := config.randomKeyIndex(att)
	if err != nil {
		return "", nil, fmt.Errorf("random key index: %w", err)
	}
	span.SetAnnotation("key_index", strconv.Itoa(keyIndex))

	var privateKey []byte

	key, found, err := p.keysTable.Get(ctx, generation, keyIndex)
	if err != nil {
		return "", nil, fmt.Errorf("get key: %w", err)
	}
	if !found {
		p.logger.InfoContext(ctx, "generating new cipher key", "generation", generation, "key_index", keyIndex)

		// Technically, this operation may be executed concurrently by multiple instances, causing a race condition.
		// However, we don't care about it. Conflict is unlikely due to 128-bit key ref and small size of the pool.
		// This may lead to two different keys sharing the same key index but that's not a problem in practice.
		// Decryption retrieves keys based on key ref, while encryption will favor one of these keys.
		key, privateKey, err = p.GenerateKey(ctx, att, keyIndex)
		if err != nil {
			return "", nil, fmt.Errorf("generate key: %w", err)
		}

		if p.cache != nil {
			p.cache.put(key.KeyRef, privateKey)
		}
	} else {
		// Existing key — try cache before KMS.
		if p.cache != nil {
			if dek, ok := p.cache.get(key.KeyRef); ok {
				privateKey = dek
			}
		}
		if privateKey == nil {
			if err := p.VerifyKey(ctx, att, key); err != nil {
				return "", nil, fmt.Errorf("verify key: %w", err)
			}
			privateKey, err = p.combineShares(ctx, att, config, key.EncryptedShares)
			if err != nil {
				return "", nil, fmt.Errorf("combine shares: %w", err)
			}

			if p.cache != nil {
				p.cache.put(key.KeyRef, privateKey)
			}
		}
	}
	span.SetAnnotation("key_ref", key.KeyRef)

	encrypted, err := aesgcm.Encrypt(att, privateKey, plaintext, additionalData)
	if err != nil {
		return "", nil, fmt.Errorf("encrypt: %w", err)
	}

	ct := Ciphertext{
		Version:       3,
		EncryptedData: encrypted,
	}

	encoded, err := ct.EncodeBinary()
	if err != nil {
		return "", nil, fmt.Errorf("encode ciphertext: %w", err)
	}
	return key.KeyRef, encoded, nil
}

// Decrypt decrypts the ciphertext using the latest cipher key from the Pool referenced by the keyRef.
//
// The key is verified against the attestation and migrated to the current generation if needed.
// If a DEK cache is configured, cached keys bypass DynamoDB and KMS on hit.
func (p *Pool) Decrypt(ctx context.Context, att *enclave.Attestation, keyRef string, ciphertext []byte, additionalData []byte) (plaintext []byte, err error) {
	ctx, span := tracing.Trace(ctx, "encryption.Pool.Decrypt", tracing.WithAnnotation("key_ref", keyRef))
	defer func() {
		span.RecordError(err)
		span.End()
	}()

	decoded, err := DecodeCiphertextBytes(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	// Try cache.
	var privateKey []byte
	if p.cache != nil {
		if dek, ok := p.cache.get(keyRef); ok {
			privateKey = dek
		}
	}

	// Cache miss — full fetch with singleflight dedup.
	if privateKey == nil {
		privateKey, err = p.fetchDEK(ctx, att, keyRef)
		if err != nil {
			return nil, err
		}
	}

	// Decrypt data.
	var decrypted []byte
	switch decoded.Version {
	case 1:
		decrypted, err = aescbc.Decrypt(privateKey, decoded.EncryptedData)
	case 2, 3:
		decrypted, err = aesgcm.Decrypt(privateKey, decoded.EncryptedData, additionalData)
	}
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return decrypted, nil
}

// fetchDEK retrieves a DEK through the full path: DynamoDB lookup, attestation
// verification, KMS share decryption, and Shamir combine. It uses singleflight
// to deduplicate concurrent fetches for the same keyRef, and populates the cache.
func (p *Pool) fetchDEK(ctx context.Context, att *enclave.Attestation, keyRef string) (privateKey []byte, err error) {
	// Singleflight: if another goroutine is already fetching this keyRef, wait.
	if p.cache != nil {
		started, wait := p.cache.waitOrStart(keyRef)
		if !started {
			return wait()
		}
		defer func() { p.cache.finish(keyRef, privateKey, err) }()
	}

	key, found, err := p.keysTable.GetLatestByKeyRef(ctx, keyRef, false)
	if err != nil {
		return nil, fmt.Errorf("get latest key: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("key not found")
	}
	if err := p.VerifyKey(ctx, att, key); err != nil {
		return nil, fmt.Errorf("verify key: %w", err)
	}

	config, err := p.getConfig(key.Generation)
	if err != nil {
		return nil, fmt.Errorf("get config: %w", err)
	}
	if !config.areSharesValid(key.EncryptedShares) {
		return nil, fmt.Errorf("shares are invalid")
	}

	privateKey, err = p.combineShares(ctx, att, config, key.EncryptedShares)
	if err != nil {
		return nil, fmt.Errorf("combine shares: %w", err)
	}

	if p.cache != nil {
		p.cache.put(keyRef, privateKey)
	}

	// Trigger migration if needed. Migration is synchronous but non-fatal:
	// failure is logged and does not affect the returned DEK.
	if p.keyNeedsMigration(key) {
		if err := p.migrateKey(ctx, att, key, privateKey); err != nil {
			p.logger.ErrorContext(ctx, "migrating key failed", "error", err, "key_ref", key.KeyRef, "generation", key.Generation, "key_index", key.KeyIndex)
		}
	}

	return privateKey, nil
}

// RotateKey marks a key as inactive by setting its KeyIndex to a negative value. It won't be used for encrypting
// new data while remaining accessible for decrypting existing data.
//
// Please note that as long as the key is referenced by any encrypted data, it will continue being automatically
// migrated to newer generations.
func (p *Pool) RotateKey(ctx context.Context, att *enclave.Attestation, keyRef string) (err error) {
	ctx, span := tracing.Trace(ctx, "encryption.Pool.RotateKey", tracing.WithAnnotation("key_ref", keyRef))
	defer func() {
		span.RecordError(err)
		span.End()
	}()

	key, found, err := p.keysTable.GetLatestByKeyRef(ctx, keyRef, true)
	if err != nil {
		return fmt.Errorf("get cipher key: %w", err)
	}
	if !found {
		return fmt.Errorf("cipher key not found")
	}

	now := time.Now()
	key.KeyIndex = nil
	key.InactiveSince = &now

	hash, err := key.Hash()
	if err != nil {
		return fmt.Errorf("hash key: %w", err)
	}

	keyAtt, err := p.attester.GetAttestation(ctx, nil, hash)
	if err != nil {
		return fmt.Errorf("get attestation: %w", err)
	}
	key.Attestation = keyAtt.Document()
	if err := keyAtt.Close(); err != nil {
		return fmt.Errorf("close attestation: %w", err)
	}

	if err := p.keysTable.Deactivate(ctx, key.KeyRef, key.Generation, now, keyAtt.Document()); err != nil {
		return fmt.Errorf("deactivate key: %w", err)
	}

	if p.cache != nil {
		p.cache.delete(keyRef)
	}

	return nil
}

// CleanupUnusedKeys removes cipher keys that are no longer used by any encrypted data.
//
// It is inefficient and best-effort, not guaranteed to complete in a single pass, as it is
// assumed to be called infrequently. It can, however, be retried until the returned count is 0.
func (p *Pool) CleanupUnusedKeys(ctx context.Context) (deleted int, err error) {
	ctx, span := tracing.Trace(ctx, "encryption.Pool.CleanupUnusedKeys")
	defer func() {
		span.RecordError(err)
		span.End()
	}()

	var cursor *string
	for {
		keys, nextCursor, err := p.keysTable.ScanInactive(ctx, cursor)
		if err != nil {
			return deleted, fmt.Errorf("list generation key refs: %w", err)
		}
		for _, key := range keys {
			isUsedAnywhere := false
			for _, dataTable := range p.dataTables {
				isUsed, err := dataTable.ReferencesCipherKeyRef(ctx, key.KeyRef)
				if err != nil {
					return deleted, fmt.Errorf("count by key ref in table %q: %w", dataTable.TableARN(), err)
				}
				if isUsed {
					isUsedAnywhere = true
					break
				}
			}
			if !isUsedAnywhere {
				p.logger.InfoContext(ctx, "deleting unused cipher key", "key_ref", key.KeyRef, "generation", key.Generation, "key_index", key.KeyIndex)
				if err := p.keysTable.Delete(ctx, key.KeyRef, key.Generation); err != nil {
					return deleted, fmt.Errorf("delete cipher key by ref %q: %w", key.KeyRef, err)
				}
				deleted++
			}
		}
		if nextCursor == nil {
			break
		}
		cursor = nextCursor
	}

	return deleted, nil
}

func (p *Pool) currentConfig() (int, *Config) {
	index := len(p.configs) - 1
	return index, p.configs[index]
}

func (p *Pool) getConfig(configVersion int) (*Config, error) {
	if configVersion < 0 || configVersion >= len(p.configs) {
		return nil, fmt.Errorf("config version out of bounds")
	}
	return p.configs[configVersion], nil
}

func (p *Pool) GenerateKey(ctx context.Context, att *enclave.Attestation, keyIndex int) (_ *data.CipherKey, _ []byte, err error) {
	ctx, span := tracing.Trace(ctx, "encryption.Pool.GenerateKey", tracing.WithAnnotation("key_index", strconv.Itoa(keyIndex)))
	defer func() {
		span.RecordError(err)
		span.End()
	}()

	generation, config := p.currentConfig()
	span.SetAnnotation("generation", strconv.Itoa(generation))

	// Generate a random AES-256 key (32 bytes) using the attestation as a source of randomness
	privateKey := make([]byte, 32) // AES-256 requires a 32-byte key
	_, err = io.ReadFull(att, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("generate private key: %w", err)
	}

	refBytes := make([]byte, 16)
	_, err = io.ReadFull(att, refBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key ref: %w", err)
	}
	keyRef := base64.RawURLEncoding.EncodeToString(refBytes)

	shares, err := shamir.Split(privateKey, len(config.RemoteKeys), config.Threshold)
	if err != nil {
		return nil, nil, fmt.Errorf("split private key: %w", err)
	}

	i := 0
	encryptedShares := make(map[string]string)
	for remoteKeyID, remoteKey := range config.RemoteKeys {
		encryptedShare, err := remoteKey.Encrypt(ctx, att, shares[i])
		if err != nil {
			return nil, nil, fmt.Errorf("encrypt share %d: %w", i, err)
		}
		encryptedShares[remoteKeyID] = encryptedShare
		i++
	}

	key := &data.CipherKey{
		Generation:      generation,
		KeyIndex:        &keyIndex,
		KeyRef:          keyRef,
		EncryptedShares: encryptedShares,
		CreatedAt:       time.Now(),
	}

	hash, err := key.Hash()
	if err != nil {
		return nil, nil, fmt.Errorf("hash key: %w", err)
	}

	keyAtt, err := p.attester.GetAttestation(ctx, nil, hash)
	if err != nil {
		return nil, nil, fmt.Errorf("get attestation: %w", err)
	}
	key.Attestation = keyAtt.Document()
	if err := keyAtt.Close(); err != nil {
		return nil, nil, fmt.Errorf("close attestation: %w", err)
	}

	alreadyExists, err := p.keysTable.Create(ctx, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create key: %w", err)
	}
	if alreadyExists {
		return nil, nil, fmt.Errorf("key already exists")
	}

	return key, privateKey, nil
}

func (p *Pool) VerifyKey(ctx context.Context, att *enclave.Attestation, key *data.CipherKey) (err error) {
	_, span := tracing.Trace(ctx, "encryption.Pool.verifyKey")
	defer func() {
		span.RecordError(err)
		span.End()
	}()

	hash, err := key.Hash()
	if err != nil {
		return fmt.Errorf("hash key: %w", err)
	}

	keyAtt, err := nitro.Parse(key.Attestation)
	if err != nil {
		return fmt.Errorf("parse attestation: %w", err)
	}

	opts := []nitro.ValidateOption{
		nitro.WithExpectedUserData(hash),
		// attestation is stored long-term, so we can only ensure it was valid at the time of creation
		nitro.WithTime(keyAtt.Timestamp),
		// only accept attestations created by the same IAM role
		nitro.WithExpectedPCRs(map[int]string{
			3: att.PCRs[3], // PCR3 is the hash of the IAM role
		}),
		// expect the same root certificate as the one attested by the enclave
		nitro.WithRootFingerprint(att.RootCertFingerprint()),
	}
	if err := keyAtt.Validate(opts...); err != nil {
		return fmt.Errorf("validate attestation: %w", err)
	}

	if err := keyAtt.Verify(); err != nil {
		return fmt.Errorf("verify attestation: %w", err)
	}

	return nil
}

func (p *Pool) keyNeedsMigration(key *data.CipherKey) bool {
	generation, _ := p.currentConfig()
	return key.Generation < generation
}

func (p *Pool) migrateKey(ctx context.Context, att *enclave.Attestation, key *data.CipherKey, privateKey []byte) (err error) {
	ctx, span := tracing.Trace(ctx, "encryption.Pool.migrateKey")
	defer func() {
		span.RecordError(err)
		span.End()
	}()

	generation, config := p.currentConfig()
	span.SetAnnotation("generation", strconv.Itoa(generation))

	p.logger.InfoContext(ctx, "migrating key", "key_ref", key.KeyRef, "generation", key.Generation, "key_index", key.KeyIndex, "new_generation", generation)

	shares, err := shamir.Split(privateKey, len(config.RemoteKeys), config.Threshold)
	if err != nil {
		return fmt.Errorf("split private key: %w", err)
	}

	i := 0
	encryptedShares := make(map[string]string)
	for remoteKeyID, remoteKey := range config.RemoteKeys {
		encryptedShare, err := remoteKey.Encrypt(ctx, att, shares[i])
		if err != nil {
			return fmt.Errorf("encrypt share %d: %w", i, err)
		}
		encryptedShares[remoteKeyID] = encryptedShare
		i++
	}

	migratedKey := &data.CipherKey{
		Generation:      generation,
		KeyIndex:        nil,
		KeyRef:          key.KeyRef,
		EncryptedShares: encryptedShares,
		CreatedAt:       key.CreatedAt,
	}

	hash, err := migratedKey.Hash()
	if err != nil {
		return fmt.Errorf("hash key: %w", err)
	}

	keyAtt, err := p.attester.GetAttestation(ctx, nil, hash)
	if err != nil {
		return fmt.Errorf("get attestation: %w", err)
	}
	migratedKey.Attestation = keyAtt.Document()
	if err := keyAtt.Close(); err != nil {
		return fmt.Errorf("close attestation: %w", err)
	}

	alreadyExists, err := p.keysTable.Create(ctx, migratedKey)
	if err != nil {
		return fmt.Errorf("create key: %w", err)
	}

	// We don't care if we encounter an index collision, as this means the key is already migrated.
	if alreadyExists {
		p.logger.InfoContext(ctx, "attempted to migrate key that already exists", "key_ref", key.KeyRef, "generation", generation)
	}

	return nil
}

func (p *Pool) combineShares(ctx context.Context, att *enclave.Attestation, config *Config, shares map[string]string) (_ []byte, err error) {
	ctx, span := tracing.Trace(ctx, "encryption.Pool.combineShares")
	defer func() {
		span.RecordError(err)
		span.End()
	}()

	decryptedShares := make([][]byte, 0, len(shares))
	for remoteKeyID, encryptedShare := range shares {
		remoteKey, ok := config.RemoteKeys[remoteKeyID]
		if !ok {
			return nil, fmt.Errorf("remote key not found: %s", remoteKeyID)
		}
		decryptedShare, err := remoteKey.Decrypt(ctx, att, encryptedShare)
		if err != nil {
			p.logger.ErrorContext(ctx, "decrypt share failed", "error", err, "remote_key_id", remoteKeyID)
			continue
		}
		decryptedShares = append(decryptedShares, decryptedShare)
	}

	privateKey, err := shamir.Combine(decryptedShares)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}
