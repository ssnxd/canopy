package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	minMemory      uint32 = 8
	maxMemory      uint32 = 256 * 1024
	maxIterations  uint32 = 10
	maxParallelism uint8  = 16
	minSaltLength  uint32 = 8
	maxSaltLength  uint32 = 64
	minKeyLength   uint32 = 16
	maxKeyLength   uint32 = 64

	maxEncodedHashLength = 512
)

var errInvalidArgon2idHash = errors.New("password: invalid argon2id hash")

type Hasher interface {
	Hash(ctx context.Context, password string) (string, error)
	Verify(ctx context.Context, password, encodedHash string) (ok bool, needsRehash bool, err error)
}

type Argon2idHasher struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func DefaultHasher() *Argon2idHasher {
	return &Argon2idHasher{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func (h *Argon2idHasher) Hash(ctx context.Context, password string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}
	p := h.params()
	if err := p.validate(); err != nil {
		return "", err
	}
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		p.Memory,
		p.Iterations,
		p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

func (h *Argon2idHasher) Verify(ctx context.Context, password, encodedHash string) (bool, bool, error) {
	select {
	case <-ctx.Done():
		return false, false, ctx.Err()
	default:
	}
	current := h.params()
	if err := current.validate(); err != nil {
		return false, false, err
	}
	params, salt, key, err := parseArgon2id(encodedHash)
	if err != nil {
		return false, false, err
	}
	other := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(key)))
	ok := subtle.ConstantTimeCompare(key, other) == 1
	return ok, ok && !current.equal(params), nil
}

func (h *Argon2idHasher) params() Argon2idHasher {
	p := *h
	if p.Memory == 0 {
		p.Memory = 64 * 1024
	}
	if p.Iterations == 0 {
		p.Iterations = 3
	}
	if p.Parallelism == 0 {
		p.Parallelism = 2
	}
	if p.SaltLength == 0 {
		p.SaltLength = 16
	}
	if p.KeyLength == 0 {
		p.KeyLength = 32
	}
	return p
}

func (h Argon2idHasher) equal(other Argon2idHasher) bool {
	return h.Memory == other.Memory &&
		h.Iterations == other.Iterations &&
		h.Parallelism == other.Parallelism &&
		h.SaltLength == other.SaltLength &&
		h.KeyLength == other.KeyLength
}

func (h Argon2idHasher) validate() error {
	if h.Memory < minMemory || h.Memory > maxMemory {
		return fmt.Errorf("%w: memory must be between %d and %d KiB", errInvalidArgon2idHash, minMemory, maxMemory)
	}
	if h.Iterations == 0 || h.Iterations > maxIterations {
		return fmt.Errorf("%w: iterations must be between 1 and %d", errInvalidArgon2idHash, maxIterations)
	}
	if h.Parallelism == 0 || h.Parallelism > maxParallelism {
		return fmt.Errorf("%w: parallelism must be between 1 and %d", errInvalidArgon2idHash, maxParallelism)
	}
	if h.Memory < 8*uint32(h.Parallelism) {
		return fmt.Errorf("%w: memory must be at least eight times parallelism", errInvalidArgon2idHash)
	}
	if h.SaltLength < minSaltLength || h.SaltLength > maxSaltLength {
		return fmt.Errorf("%w: salt length must be between %d and %d bytes", errInvalidArgon2idHash, minSaltLength, maxSaltLength)
	}
	if h.KeyLength < minKeyLength || h.KeyLength > maxKeyLength {
		return fmt.Errorf("%w: key length must be between %d and %d bytes", errInvalidArgon2idHash, minKeyLength, maxKeyLength)
	}
	return nil
}

func parseArgon2id(encoded string) (Argon2idHasher, []byte, []byte, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedHashLength {
		return Argon2idHasher{}, nil, nil, errInvalidArgon2idHash
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return Argon2idHasher{}, nil, nil, errInvalidArgon2idHash
	}
	var p Argon2idHasher
	fields := strings.Split(parts[3], ",")
	if len(fields) != 3 {
		return Argon2idHasher{}, nil, nil, errInvalidArgon2idHash
	}
	seen := make(map[string]bool, len(fields))
	for _, field := range fields {
		kv := strings.SplitN(field, "=", 2)
		if len(kv) != 2 || seen[kv[0]] {
			return Argon2idHasher{}, nil, nil, errInvalidArgon2idHash
		}
		seen[kv[0]] = true
		switch kv[0] {
		case "m":
			n, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return Argon2idHasher{}, nil, nil, errInvalidArgon2idHash
			}
			p.Memory = uint32(n)
		case "t":
			n, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return Argon2idHasher{}, nil, nil, errInvalidArgon2idHash
			}
			p.Iterations = uint32(n)
		case "p":
			n, err := strconv.ParseUint(kv[1], 10, 8)
			if err != nil {
				return Argon2idHasher{}, nil, nil, errInvalidArgon2idHash
			}
			p.Parallelism = uint8(n)
		default:
			return Argon2idHasher{}, nil, nil, errInvalidArgon2idHash
		}
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Argon2idHasher{}, nil, nil, errInvalidArgon2idHash
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Argon2idHasher{}, nil, nil, errInvalidArgon2idHash
	}
	p.SaltLength = uint32(len(salt))
	p.KeyLength = uint32(len(key))
	if err := p.validate(); err != nil {
		return Argon2idHasher{}, nil, nil, err
	}
	return p, salt, key, nil
}
