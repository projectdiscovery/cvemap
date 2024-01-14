package model

import (
	"context"
	"time"

	"github.com/cenkalti/backoff"
)

func NewExpBackOff(ctx context.Context, start, max time.Duration) backoff.BackOffContext {
	bf := backoff.NewExponentialBackOff()
	bf.InitialInterval, bf.MaxElapsedTime = start, max
	return backoff.WithContext(bf, ctx)
}
