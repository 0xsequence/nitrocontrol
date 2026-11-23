package attestation_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0xsequence/nitrocontrol/attestation"
	"github.com/0xsequence/nitrocontrol/enclave"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestMiddleware(t *testing.T) {
	enc, err := enclave.New(context.Background(), enclave.DummyProvider(nil), nil)
	require.NoError(t, err)

	errorFn := func(w http.ResponseWriter, err error) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(err.Error()))
	}
	loggerFromContextFn := func(ctx context.Context) *slog.Logger {
		return slog.New(slog.DiscardHandler)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(attestation.Middleware(enc, errorFn, loggerFromContextFn)(handler))
	defer srv.Close()

	tests := map[string]struct {
		request     func() (http.Header, []byte)
		wantStatus  int
		wantErrText string
	}{
		"NoNonce": {
			wantStatus: http.StatusOK,
			request: func() (http.Header, []byte) {
				return http.Header{}, []byte("test")
			},
		},
		"ValidNonce": {
			wantStatus: http.StatusOK,
			request: func() (http.Header, []byte) {
				return http.Header{
					"X-Attestation-Nonce": []string{"test"},
				}, []byte("test")
			},
		},
		"InvalidNonce": {
			wantStatus:  http.StatusBadRequest,
			wantErrText: "X-Attestation-Nonce value contains invalid characters",
			request: func() (http.Header, []byte) {
				return http.Header{
					"X-Attestation-Nonce": []string{"!@#$%^&*()"},
				}, []byte("test")
			},
		},
		"LongNonce": {
			wantStatus:  http.StatusBadRequest,
			wantErrText: "X-Attestation-Nonce value cannot be longer than 32",
			request: func() (http.Header, []byte) {
				return http.Header{
					"X-Attestation-Nonce": []string{"test-123456789012345678901234567890123"},
				}, []byte("test")
			},
		},
		"WhitespaceNonce": {
			wantStatus:  http.StatusBadRequest,
			wantErrText: "X-Attestation-Nonce value contains invalid characters",
			request: func() (http.Header, []byte) {
				return http.Header{
					"X-Attestation-Nonce": []string{"   \t a  a \t  "},
				}, []byte("test")
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			header, reqBody := test.request()
			req, err := http.NewRequest("POST", srv.URL, bytes.NewBuffer(reqBody))
			require.NoError(t, err)
			req.Header = header

			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			defer func() {
				require.NoError(t, resp.Body.Close())
			}()
			body, _ := io.ReadAll(resp.Body)

			require.Equal(t, test.wantStatus, resp.StatusCode, string(body))
			if test.wantErrText != "" {
				require.Contains(t, string(body), test.wantErrText)
			}
		})
	}
}

func TestMiddlewareUserData(t *testing.T) {
	enc, err := enclave.New(context.Background(), enclave.DummyProvider(nil), nil)
	require.NoError(t, err)

	errorFn := func(w http.ResponseWriter, err error) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(err.Error()))
	}
	loggerFromContextFn := func(ctx context.Context) *slog.Logger {
		return slog.New(slog.DiscardHandler)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("response"))
	})

	tests := map[string]struct {
		opts         []attestation.Option
		header       http.Header
		wantPreimage string
		wantVersion  string
	}{
		"V1": {
			header:       http.Header{"Oms-Wallet-Signature": []string{"sig"}},
			wantPreimage: "POST /rpc\nrequest\nresponse",
			wantVersion:  "Sequence/1:",
		},
		"V2HeaderPresent": {
			opts:         []attestation.Option{attestation.WithBoundHeader("Oms-Wallet-Signature")},
			header:       http.Header{"Oms-Wallet-Signature": []string{"sig"}},
			wantPreimage: "POST /rpc\nsig\nrequest\nresponse",
			wantVersion:  "Sequence/2:",
		},
		"V2HeaderAbsent": {
			opts:         []attestation.Option{attestation.WithBoundHeader("Oms-Wallet-Signature")},
			header:       http.Header{},
			wantPreimage: "POST /rpc\n\nrequest\nresponse",
			wantVersion:  "Sequence/2:",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(attestation.Middleware(enc, errorFn, loggerFromContextFn, test.opts...)(handler))
			defer srv.Close()

			req, err := http.NewRequest("POST", srv.URL+"/rpc", bytes.NewBufferString("request"))
			require.NoError(t, err)
			req.Header = test.header

			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			defer func() {
				require.NoError(t, resp.Body.Close())
			}()
			require.Equal(t, http.StatusOK, resp.StatusCode)

			doc, err := base64.StdEncoding.DecodeString(resp.Header.Get("X-Attestation-Document"))
			require.NoError(t, err)
			var coseSign1 []cbor.RawMessage
			require.NoError(t, cbor.Unmarshal(doc, &coseSign1))
			var payload []byte
			require.NoError(t, cbor.Unmarshal(coseSign1[2], &payload))
			var rawDoc struct {
				UserData []byte `cbor:"user_data"`
			}
			require.NoError(t, cbor.Unmarshal(payload, &rawDoc))

			sum := sha256.Sum256([]byte(test.wantPreimage))
			require.Equal(t, test.wantVersion+base64.StdEncoding.EncodeToString(sum[:]), string(rawDoc.UserData))
		})
	}
}
