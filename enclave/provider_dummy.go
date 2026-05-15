package enclave

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/0xsequence/nsm/request"
	"github.com/0xsequence/nsm/response"
	"github.com/fxamacker/cbor/v2"
)

// DummyProvider returns a Provider that simulates the Nitro Security Module for testing and local development.
// The random parameter controls the entropy source for session reads (used by enclave key generation and
// attestation randomness). It does not affect the CA key pair, which is always generated using crypto/rand
// to ensure cryptographic security.
func DummyProvider(random io.Reader) func() (Session, error) {
	if random == nil {
		random = rand.Reader
	}

	// Generate an ephemeral CA key pair and self-signed certificate once per provider instance.
	// This avoids shipping static key material in the source code.
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return func() (Session, error) {
			return nil, fmt.Errorf("failed to generate CA key: %v", err)
		}
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return func() (Session, error) {
			return nil, fmt.Errorf("failed to generate serial number: %v", err)
		}
	}

	caTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Dummy"},
			CommonName:   "dummy.nitro-enclaves",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return func() (Session, error) {
			return nil, fmt.Errorf("failed to create CA certificate: %v", err)
		}
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return func() (Session, error) {
			return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
		}
	}

	return func() (Session, error) {
		return &dummySession{
			random:     random,
			privateKey: caKey,
			caCert:     caCert,
			caCertDER:  caCertDER,
		}, nil
	}
}

type dummySession struct {
	privateKey *rsa.PrivateKey
	caCert     *x509.Certificate
	caCertDER  []byte
	random     io.Reader
	closed     atomic.Bool
}

func (d *dummySession) Read(p []byte) (n int, err error) {
	if d.closed.Load() {
		return 0, fmt.Errorf("session is closed")
	}
	return d.random.Read(p)
}

func (d *dummySession) Close() error {
	d.closed.Store(true)
	return nil
}

func (d *dummySession) Send(ctx context.Context, req request.Request) (response.Response, error) {
	switch req := req.(type) {
	case *request.Attestation:
		return d.handleAttestation(req)
	case *request.DescribePCR:
		return d.handleDescribePCR(req)
	default:
		return response.Response{}, fmt.Errorf("unsupported request type: %T", req)
	}
}

func (d *dummySession) handleAttestation(req *request.Attestation) (response.Response, error) {
	certDER, privateKey, err := d.generateCertificate()
	if err != nil {
		return response.Response{}, fmt.Errorf("failed to generate certificate: %v", err)
	}

	pcr := make([]byte, 48)
	rawDoc := struct {
		ModuleID    string         `cbor:"module_id"`
		Timestamp   uint64         `cbor:"timestamp"`
		Digest      string         `cbor:"digest"`
		PCRs        map[int][]byte `cbor:"pcrs"`
		Certificate []byte         `cbor:"certificate"`
		CABundle    [][]byte       `cbor:"cabundle"`
		PublicKey   []byte         `cbor:"public_key"`
		UserData    []byte         `cbor:"user_data"`
		Nonce       []byte         `cbor:"nonce"`
	}{
		ModuleID:  "dummy-module",
		Timestamp: uint64(time.Now().Unix() * 1000),
		Digest:    "SHA384",
		PCRs: map[int][]byte{
			0: pcr,
			1: pcr,
			2: pcr,
			3: pcr,
		},
		Certificate: certDER,
		CABundle:    [][]byte{d.caCertDER},
		PublicKey:   req.PublicKey,
		UserData:    req.UserData,
		Nonce:       req.Nonce,
	}

	rawDocBytes, err := cbor.Marshal(rawDoc)
	if err != nil {
		return response.Response{}, fmt.Errorf("failed to marshal raw document: %v", err)
	}

	sigStructCBOR, err := cbor.Marshal([]any{"Signature1", []byte{}, []byte{}, rawDocBytes})
	if err != nil {
		return response.Response{}, fmt.Errorf("failed to marshal signature structure: %v", err)
	}
	hash := crypto.SHA384.New()
	if _, err := hash.Write(sigStructCBOR); err != nil {
		return response.Response{}, fmt.Errorf("failed to hash signature structure: %v", err)
	}
	digest := hash.Sum(nil)

	derSig, err := privateKey.Sign(rand.Reader, digest, crypto.SHA384)
	if err != nil {
		return response.Response{}, fmt.Errorf("failed to sign digest: %v", err)
	}

	var esig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(derSig, &esig); err != nil {
		return response.Response{}, fmt.Errorf("failed to unmarshal ASN.1 signature: %v", err)
	}

	rBytes := esig.R.FillBytes(make([]byte, 48)) // 48 bytes for P-384
	sBytes := esig.S.FillBytes(make([]byte, 48))
	sig := append(rBytes, sBytes...)

	document, err := cbor.Marshal([]any{[]byte{}, struct{}{}, rawDocBytes, sig})
	if err != nil {
		return response.Response{}, fmt.Errorf("failed to marshal COSE_Sign1: %v", err)
	}

	res := response.Response{
		Attestation: &response.Attestation{
			Document: document,
		},
	}
	return res, nil
}

func (d *dummySession) handleDescribePCR(req *request.DescribePCR) (response.Response, error) {
	hash := make([]byte, 48)
	res := response.Response{
		DescribePCR: &response.DescribePCR{
			Lock: true,
			Data: hash,
		},
	}
	return res, nil
}

func (d *dummySession) generateCertificate() ([]byte, *ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Dummy"},
			CommonName:   "dummy.nitro-enclaves",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, d.caCert, &privateKey.PublicKey, d.privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	return certBytes, privateKey, nil
}
