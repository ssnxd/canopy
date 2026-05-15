// Package ratelimit provides Canopy's built-in in-memory RateLimiter.
//
// The limiter combines request-rate buckets with failed-attempt counters for
// normalized identities and IP addresses. It is suitable for tests and
// single-process deployments; horizontally scaled production systems should use
// a shared implementation behind canopy.RateLimiter.
package ratelimit
