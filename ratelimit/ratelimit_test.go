package ratelimit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ssnxd/canopy"
	"golang.org/x/time/rate"
)

func TestLimiterBlocksAfterFailedIdentityAttemptsAndResetsOnSuccess(t *testing.T) {
	now := time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC)
	limiter := New(Config{
		IPRate:        rate.Inf,
		IPBurst:       1,
		IdentityRate:  rate.Inf,
		IdentityBurst: 1,
		FailureLimit:  2,
		FailureWindow: time.Minute,
		Now: func() time.Time {
			return now
		},
	})
	req := canopy.RateLimitRequest{Email: "ADA@example.com", IPAddress: "127.0.0.1", Route: "/sign-in/email"}
	if err := limiter.Allow(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	limiter.Report(context.Background(), req, false)
	limiter.Report(context.Background(), req, false)
	if err := limiter.Allow(context.Background(), req); !errors.Is(err, canopy.ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	snapshot := limiter.Snapshot(req)
	if snapshot.IdentityFailures != 2 || snapshot.IPFailures != 2 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	limiter.Report(context.Background(), req, true)
	if err := limiter.Allow(context.Background(), req); !errors.Is(err, canopy.ErrRateLimited) {
		t.Fatalf("IP failure bucket should still block, err = %v", err)
	}
	now = now.Add(time.Minute + time.Second)
	if err := limiter.Allow(context.Background(), req); err != nil {
		t.Fatalf("expired limiter still blocked: %v", err)
	}
}
