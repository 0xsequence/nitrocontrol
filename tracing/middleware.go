package tracing

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/traceid"
)

const defaultHeaderName = "X-Sequence-Span"

type middlewareConfig struct {
	headerName     string
	skipStackTrace bool
}

// MiddlewareOption configures the tracing middleware.
type MiddlewareOption func(*middlewareConfig)

// WithHeaderName sets the response header name for the serialized span tree.
// Default: "X-Sequence-Span".
func WithHeaderName(name string) MiddlewareOption {
	return func(c *middlewareConfig) {
		if name != "" {
			c.headerName = name
		}
	}
}

// WithoutStackTrace prevents stack traces from being captured in span error metadata.
func WithoutStackTrace() MiddlewareOption {
	return func(c *middlewareConfig) {
		c.skipStackTrace = true
	}
}

func Middleware(errorFn func(http.ResponseWriter, error), opts ...MiddlewareOption) func(http.Handler) http.Handler {
	cfg := &middlewareConfig{
		headerName: defaultHeaderName,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body bytes.Buffer
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			ww.Tee(&body)
			ww.Discard()

			reqCtx := r.Context()
			if cfg.skipStackTrace {
				reqCtx = withTracingConfig(reqCtx, &tracingConfig{skipStackTrace: true})
			}

			tid := traceid.FromContext(reqCtx)
			ctx, span := Trace(
				reqCtx,
				r.URL.Path,
				WithSpanKind(SpanKindServer),
				WithMetadata(map[string]any{
					"sequence.traceid": tid,
					"net.host.name":   r.Host,
					"server.address":  r.Host,
					"http.method":     r.Method,
					"http.url":        r.URL.Redacted(),
					"url.path":        r.URL.Path,
				}),
			)

			next.ServeHTTP(ww, r.WithContext(ctx))

			span.SetStatus(ww.Status())
			span.End()

			spanJSON, err := json.Marshal(span)
			if err != nil {
				errorFn(w, err)
				return
			}

			w.Header().Set(cfg.headerName, string(spanJSON))

			w.WriteHeader(ww.Status())
			if _, err := body.WriteTo(w); err != nil {
				errorFn(w, err)
				return
			}
		})
	}
}
