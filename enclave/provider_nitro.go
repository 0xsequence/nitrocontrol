package enclave

import (
	"context"

	"github.com/hf/nsm"
)

func NitroProvider(_ context.Context) (Session, error) {
	return nsm.OpenDefaultSession()
}
