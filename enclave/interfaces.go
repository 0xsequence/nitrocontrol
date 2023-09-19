package enclave

import (
	"context"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

type Provider func(ctx context.Context) (Session, error)

type Session interface {
	io.ReadCloser
	Send(request request.Request) (response.Response, error)
}

type KMS interface {
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
	GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
}
