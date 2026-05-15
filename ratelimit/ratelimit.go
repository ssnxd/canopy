package ratelimit

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/ssnxd/canopy"
	"golang.org/x/time/rate"
)

type Config struct {
	IPRate          rate.Limit
	IPBurst         int
	IdentityRate    rate.Limit
	IdentityBurst   int
	FailureLimit    int
	FailureWindow   time.Duration
	CleanupInterval time.Duration
	Now             func() time.Time
}

type Limiter struct {
	cfg         Config
	mu          sync.Mutex
	ips         map[string]*bucket
	identities  map[string]*bucket
	failures    map[string]failureCounter
	lastCleanup time.Time
}

type bucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type failureCounter struct {
	Count   int
	ResetAt time.Time
}

type Snapshot struct {
	IPFailures       int
	IdentityFailures int
	IPResetAt        time.Time
	IdentityResetAt  time.Time
}

func New(config Config) *Limiter {
	if config.IPRate == 0 {
		config.IPRate = rate.Every(2 * time.Second)
	}
	if config.IPBurst == 0 {
		config.IPBurst = 10
	}
	if config.IdentityRate == 0 {
		config.IdentityRate = rate.Every(6 * time.Second)
	}
	if config.IdentityBurst == 0 {
		config.IdentityBurst = 5
	}
	if config.FailureLimit == 0 {
		config.FailureLimit = 5
	}
	if config.FailureWindow == 0 {
		config.FailureWindow = 15 * time.Minute
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = time.Minute
	}
	return &Limiter{
		cfg:        config,
		ips:        map[string]*bucket{},
		identities: map[string]*bucket{},
		failures:   map[string]failureCounter{},
	}
}

func (l *Limiter) Allow(ctx context.Context, req canopy.RateLimitRequest) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	now := l.now()
	ipKey := key("ip", req.IPAddress)
	identityKey := key("identity", req.Email)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanup(now)
	if !l.allowBucket(l.ips, ipKey, l.cfg.IPRate, l.cfg.IPBurst, now) {
		return canopy.ErrRateLimited
	}
	if identityKey != "" && !l.allowBucket(l.identities, identityKey, l.cfg.IdentityRate, l.cfg.IdentityBurst, now) {
		return canopy.ErrRateLimited
	}
	if l.isFailureBlocked(ipKey, now) || (identityKey != "" && l.isFailureBlocked(identityKey, now)) {
		return canopy.ErrRateLimited
	}
	return nil
}

func (l *Limiter) Report(ctx context.Context, req canopy.RateLimitRequest, success bool) {
	now := l.now()
	ipKey := key("ip", req.IPAddress)
	identityKey := key("identity", req.Email)
	l.mu.Lock()
	defer l.mu.Unlock()
	if success {
		delete(l.failures, identityKey)
		return
	}
	l.incrementFailure(ipKey, now)
	l.incrementFailure(identityKey, now)
}

func (l *Limiter) Snapshot(req canopy.RateLimitRequest) Snapshot {
	now := l.now()
	ipKey := key("ip", req.IPAddress)
	identityKey := key("identity", req.Email)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanup(now)
	ipFailure := l.failures[ipKey]
	identityFailure := l.failures[identityKey]
	return Snapshot{
		IPFailures:       ipFailure.Count,
		IdentityFailures: identityFailure.Count,
		IPResetAt:        ipFailure.ResetAt,
		IdentityResetAt:  identityFailure.ResetAt,
	}
}

func (l *Limiter) allowBucket(buckets map[string]*bucket, k string, limit rate.Limit, burst int, now time.Time) bool {
	if k == "" {
		return true
	}
	b := buckets[k]
	if b == nil {
		b = &bucket{limiter: rate.NewLimiter(limit, burst)}
		buckets[k] = b
	}
	b.lastSeen = now
	return b.limiter.Allow()
}

func (l *Limiter) incrementFailure(k string, now time.Time) {
	if k == "" {
		return
	}
	f := l.failures[k]
	if f.ResetAt.IsZero() || !f.ResetAt.After(now) {
		f = failureCounter{ResetAt: now.Add(l.cfg.FailureWindow)}
	}
	f.Count++
	l.failures[k] = f
}

func (l *Limiter) isFailureBlocked(k string, now time.Time) bool {
	f := l.failures[k]
	return f.Count >= l.cfg.FailureLimit && f.ResetAt.After(now)
}

func (l *Limiter) cleanup(now time.Time) {
	if !l.lastCleanup.IsZero() && now.Sub(l.lastCleanup) < l.cfg.CleanupInterval {
		return
	}
	l.lastCleanup = now
	maxAge := l.cfg.FailureWindow
	if maxAge < l.cfg.CleanupInterval {
		maxAge = l.cfg.CleanupInterval
	}
	for k, b := range l.ips {
		if now.Sub(b.lastSeen) > maxAge {
			delete(l.ips, k)
		}
	}
	for k, b := range l.identities {
		if now.Sub(b.lastSeen) > maxAge {
			delete(l.identities, k)
		}
	}
	for k, f := range l.failures {
		if !f.ResetAt.After(now) {
			delete(l.failures, k)
		}
	}
}

func (l *Limiter) now() time.Time {
	if l.cfg.Now != nil {
		return l.cfg.Now().UTC()
	}
	return time.Now().UTC()
}

func key(prefix, value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	return prefix + ":" + value
}
