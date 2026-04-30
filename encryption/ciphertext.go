package encryption

import (
	"encoding/base64"
	"fmt"
	"strings"
)

type Ciphertext struct {
	Version       int
	EncryptedData []byte
}

func (c *Ciphertext) Encode() (string, error) {
	if c.Version != 1 && c.Version != 2 {
		return "", fmt.Errorf("unsupported version: %d, only version 1 and 2 are supported", c.Version)
	}
	if len(c.EncryptedData) == 0 {
		return "", fmt.Errorf("encrypted data cannot be empty")
	}
	return fmt.Sprintf("v%d.%s", c.Version, base64.RawURLEncoding.EncodeToString(c.EncryptedData)), nil
}

func DecodeCiphertext(ciphertext string) (*Ciphertext, error) {
	parts := strings.Split(ciphertext, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	var version int
	switch parts[0] {
	case "v1":
		version = 1
	case "v2":
		version = 2
	default:
		return nil, fmt.Errorf("unsupported ciphertext version: %s", parts[0])
	}
	encryptedData, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode encrypted data: %w", err)
	}
	if len(encryptedData) == 0 {
		return nil, fmt.Errorf("encrypted data cannot be empty")
	}
	return &Ciphertext{
		Version:       version,
		EncryptedData: encryptedData,
	}, nil
}

// EncodeBinary encodes a v3 ciphertext as binary: [0x03, encrypted_data...].
func (c *Ciphertext) EncodeBinary() ([]byte, error) {
	if c.Version != 3 {
		return nil, fmt.Errorf("EncodeBinary only supports version 3, got %d", c.Version)
	}
	if len(c.EncryptedData) == 0 {
		return nil, fmt.Errorf("encrypted data cannot be empty")
	}
	out := make([]byte, 1+len(c.EncryptedData))
	out[0] = 0x03
	copy(out[1:], c.EncryptedData)
	return out, nil
}

// DecodeCiphertextBytes detects the ciphertext format from the first byte and decodes accordingly.
//   - Starts with 'v' (0x76): legacy string format ("v1." or "v2." + base64)
//   - 0x03: binary v3 format (rest is raw AES-GCM ciphertext)
func DecodeCiphertextBytes(ciphertext []byte) (*Ciphertext, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("empty ciphertext")
	}
	if ciphertext[0] == 'v' {
		return DecodeCiphertext(string(ciphertext))
	}
	if ciphertext[0] == 0x03 {
		if len(ciphertext) < 2 {
			return nil, fmt.Errorf("v3 ciphertext too short")
		}
		return &Ciphertext{
			Version:       3,
			EncryptedData: ciphertext[1:],
		}, nil
	}
	return nil, fmt.Errorf("unsupported ciphertext format: first byte 0x%02x", ciphertext[0])
}
