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
	params, salt, key, err := parseArgon2id(encodedHash)
	if err != nil {
		return false, false, err
	}
	other := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(key)))
	ok := subtle.ConstantTimeCompare(key, other) == 1
	return ok, ok && !h.params().equal(params), nil
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
		h.KeyLength == other.KeyLength
}

func parseArgon2id(encoded string) (Argon2idHasher, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return Argon2idHasher{}, nil, nil, errors.New("password: invalid argon2id hash")
	}
	var p Argon2idHasher
	for _, field := range strings.Split(parts[3], ",") {
		kv := strings.SplitN(field, "=", 2)
		if len(kv) != 2 {
			return Argon2idHasher{}, nil, nil, errors.New("password: invalid argon2id params")
		}
		n, err := strconv.ParseUint(kv[1], 10, 32)
		if err != nil {
			return Argon2idHasher{}, nil, nil, err
		}
		switch kv[0] {
		case "m":
			p.Memory = uint32(n)
		case "t":
			p.Iterations = uint32(n)
		case "p":
			p.Parallelism = uint8(n)
		}
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Argon2idHasher{}, nil, nil, err
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Argon2idHasher{}, nil, nil, err
	}
	p.SaltLength = uint32(len(salt))
	p.KeyLength = uint32(len(key))
	return p, salt, key, nil
}
