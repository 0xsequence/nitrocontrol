package data

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/fxamacker/cbor/v2"
)

// Codec defines how typed data is serialized to bytes before encryption.
type Codec interface {
	Marshal(v any) ([]byte, error)
	Unmarshal(data []byte, v any) error
}

// JSONCodec serializes data using encoding/json.
type JSONCodec struct{}

func (JSONCodec) Marshal(v any) ([]byte, error)     { return json.Marshal(v) }
func (JSONCodec) Unmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

// CBORCodec serializes data using fxamacker/cbor/v2.
// Types that need custom CBOR encoding (e.g., typeid.UUID) should implement
// cbor.Marshaler/cbor.Unmarshaler directly.
type CBORCodec struct{}

func (CBORCodec) Marshal(v any) ([]byte, error)     { return cbor.Marshal(v) }
func (CBORCodec) Unmarshal(data []byte, v any) error { return cbor.Unmarshal(data, v) }

// CiphertextValue is a []byte that supports reading from both DynamoDB String (S) and
// Binary (B) attributes for backward compatibility. It always writes as Binary (B).
type CiphertextValue []byte

// MarshalDynamoDBAttributeValue writes as DynamoDB Binary (B).
func (c CiphertextValue) MarshalDynamoDBAttributeValue() (types.AttributeValue, error) {
	return &types.AttributeValueMemberB{Value: []byte(c)}, nil
}

// UnmarshalDynamoDBAttributeValue reads either String (S) or Binary (B).
func (c *CiphertextValue) UnmarshalDynamoDBAttributeValue(av types.AttributeValue) error {
	switch v := av.(type) {
	case *types.AttributeValueMemberS:
		*c = []byte(v.Value)
		return nil
	case *types.AttributeValueMemberB:
		*c = v.Value
		return nil
	default:
		return fmt.Errorf("CiphertextValue: unsupported attribute type %T", av)
	}
}

// Encryptor encrypts plaintext bytes and returns a key reference and ciphertext bytes.
type Encryptor interface {
	Encrypt(ctx context.Context, att *enclave.Attestation, plaintext []byte, additionalData []byte) (keyID string, ciphertext []byte, err error)
}

// Decryptor decrypts ciphertext bytes and returns the plaintext.
type Decryptor interface {
	Decrypt(ctx context.Context, att *enclave.Attestation, keyID string, ciphertext []byte, additionalData []byte) ([]byte, error)
}

// EncryptedFields is the non-generic storage envelope for encrypted data.
// It is used by the Record interface and EncryptedDataTable where the codec
// and data type are not relevant.
type EncryptedFields struct {
	CipherKeyRef   string          `dynamodbav:"CipherKeyRef"`
	Ciphertext     CiphertextValue `dynamodbav:"Ciphertext"`
	CiphertextHash []byte          `dynamodbav:"CiphertextHash"`
}

// EncryptedData adds type-safe encrypt/decrypt over EncryptedFields.
// T is the plaintext data type, C is the serialization codec.
type EncryptedData[T any, C Codec] struct {
	EncryptedFields
}

// EncryptedDataJSON is EncryptedData using JSON serialization.
type EncryptedDataJSON[T any] = EncryptedData[T, JSONCodec]

// EncryptedDataCBOR is EncryptedData using CBOR serialization.
type EncryptedDataCBOR[T any] = EncryptedData[T, CBORCodec]

// Encrypt serializes data using codec C, encrypts it, and returns EncryptedData.
func Encrypt[T any, C Codec](ctx context.Context, att *enclave.Attestation, encryptor Encryptor, data T, aad string) (EncryptedData[T, C], error) {
	var codec C
	plaintext, err := codec.Marshal(data)
	if err != nil {
		return EncryptedData[T, C]{}, fmt.Errorf("marshal data: %w", err)
	}

	additionalData := []byte(aad)
	keyID, ciphertext, err := encryptor.Encrypt(ctx, att, plaintext, additionalData)
	if err != nil {
		return EncryptedData[T, C]{}, err
	}

	hash := sha256.Sum256(ciphertext)

	return EncryptedData[T, C]{
		EncryptedFields: EncryptedFields{
			CipherKeyRef:   keyID,
			Ciphertext:     CiphertextValue(ciphertext),
			CiphertextHash: hash[:],
		},
	}, nil
}

// EncryptJSON serializes data as JSON, encrypts, and returns the EncryptedFields envelope.
func EncryptJSON[T any](ctx context.Context, att *enclave.Attestation, encryptor Encryptor, data T, aad string) (EncryptedFields, error) {
	ed, err := Encrypt[T, JSONCodec](ctx, att, encryptor, data, aad)
	return ed.EncryptedFields, err
}

// EncryptCBOR serializes data as CBOR, encrypts, and returns the EncryptedFields envelope.
func EncryptCBOR[T any](ctx context.Context, att *enclave.Attestation, encryptor Encryptor, data T, aad string) (EncryptedFields, error) {
	ed, err := Encrypt[T, CBORCodec](ctx, att, encryptor, data, aad)
	return ed.EncryptedFields, err
}

// Decrypt decrypts the ciphertext and deserializes it using codec C.
func (ed EncryptedData[T, C]) Decrypt(ctx context.Context, att *enclave.Attestation, decryptor Decryptor, aad string) (T, error) {
	var zero T

	additionalData := []byte(aad)
	plaintext, err := decryptor.Decrypt(ctx, att, ed.CipherKeyRef, []byte(ed.Ciphertext), additionalData)
	if err != nil {
		return zero, err
	}

	var codec C
	var out T
	if err := codec.Unmarshal(plaintext, &out); err != nil {
		return zero, fmt.Errorf("unmarshal data: %w", err)
	}
	return out, nil
}

// EncryptedDataTable defines methods common to all tables that store encrypted data.
// It is not meant to be used directly, but rather to be embedded in a concrete table type.
type EncryptedDataTable[T Record] struct {
	db                DB
	tableARN          string
	cipherKeyRefIndex string
}

func NewEncryptedDataTable[T Record](db DB, tableARN string, cipherKeyRefIndex string) EncryptedDataTable[T] {
	return EncryptedDataTable[T]{
		db:                db,
		tableARN:          tableARN,
		cipherKeyRefIndex: cipherKeyRefIndex,
	}
}

// ReferencesCipherKeyRef checks if the table contains any records that are encrypted with the given cipher key.
func (t *EncryptedDataTable[T]) ReferencesCipherKeyRef(ctx context.Context, keyRef string) (bool, error) {
	input := &dynamodb.QueryInput{
		TableName:              &t.tableARN,
		IndexName:              &t.cipherKeyRefIndex,
		KeyConditionExpression: aws.String("CipherKeyRef = :keyRef"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":keyRef": &types.AttributeValueMemberS{Value: keyRef},
		},
		Select: types.SelectCount,
		Limit:  aws.Int32(1),
	}

	out, err := t.db.Query(ctx, input)
	if err != nil {
		return false, fmt.Errorf("query: %w", err)
	}
	return out.Count > 0, nil
}

// ListByCipherKeyRef lists records in the table that are encrypted with the given cipher key. It only returns
// the first page of results and a boolean indicating if there are more results that were not returned.
func (t *EncryptedDataTable[T]) ListByCipherKeyRef(ctx context.Context, keyRef string, pageSize int) ([]T, bool, error) {
	input := &dynamodb.QueryInput{
		TableName:              &t.tableARN,
		IndexName:              &t.cipherKeyRefIndex,
		KeyConditionExpression: aws.String("CipherKeyRef = :keyRef"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":keyRef": &types.AttributeValueMemberS{Value: keyRef},
		},
		Limit: aws.Int32(int32(pageSize)),
	}
	out, err := t.db.Query(ctx, input)
	if err != nil {
		return nil, false, fmt.Errorf("query: %w", err)
	}

	var records []T
	for _, item := range out.Items {
		// Create a properly initialized record
		var record T
		recordType := reflect.TypeOf(record)
		if recordType.Kind() == reflect.Ptr {
			// T is a pointer type, create a new instance of the underlying type
			elemType := recordType.Elem()
			newElem := reflect.New(elemType)
			record = newElem.Interface().(T)
		}

		if err := attributevalue.UnmarshalMapWithOptions(item, &record, func(o *attributevalue.DecoderOptions) {
				o.UseEncodingUnmarshalers = true
			}); err != nil {
			return nil, false, fmt.Errorf("unmarshal result: %w", err)
		}
		records = append(records, record)
	}
	return records, len(out.LastEvaluatedKey) == 0, nil
}

// UpdateEncryptedData updates the encrypted data for a record in the table.
func (t *EncryptedDataTable[T]) UpdateEncryptedData(ctx context.Context, record T) error {
	ed := record.GetEncryptedFields()
	dbKey, err := record.DatabaseKey()
	if err != nil {
		return fmt.Errorf("encode database key: %w", err)
	}

	ctAV, err := ed.Ciphertext.MarshalDynamoDBAttributeValue()
	if err != nil {
		return fmt.Errorf("marshal ciphertext: %w", err)
	}

	input := &dynamodb.UpdateItemInput{
		TableName:        &t.tableARN,
		Key:              dbKey,
		UpdateExpression: aws.String("SET CipherKeyRef = :cipherKeyRef, Ciphertext = :ciphertext, CiphertextHash = :ciphertextHash"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":cipherKeyRef":   &types.AttributeValueMemberS{Value: ed.CipherKeyRef},
			":ciphertext":     ctAV,
			":ciphertextHash": &types.AttributeValueMemberB{Value: ed.CiphertextHash},
		},
	}
	if _, err := t.db.UpdateItem(ctx, input); err != nil {
		return fmt.Errorf("update item: %w", err)
	}
	return nil
}
