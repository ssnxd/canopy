package password

import (
	"context"
	"strings"
	"testing"
)

func TestArgon2idHashVerifyAndRehash(t *testing.T) {
	h := &Argon2idHasher{Memory: 1024, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16}
	hash, err := h.Hash(context.Background(), "secret-pass")
	if err != nil {
		t.Fatal(err)
	}
	ok, needsRehash, err := h.Verify(context.Background(), "secret-pass", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || needsRehash {
		t.Fatalf("ok=%v needsRehash=%v", ok, needsRehash)
	}
	stronger := &Argon2idHasher{Memory: 2048, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16}
	ok, needsRehash, err = stronger.Verify(context.Background(), "secret-pass", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || !needsRehash {
		t.Fatalf("ok=%v needsRehash=%v, want valid hash needing rehash", ok, needsRehash)
	}
}

func TestArgon2idRehashOnSaltLengthChange(t *testing.T) {
	weak := &Argon2idHasher{Memory: 1024, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16}
	hash, err := weak.Hash(context.Background(), "secret-pass")
	if err != nil {
		t.Fatal(err)
	}
	// Only the salt length changes. The rehash signal must still fire.
	longerSalt := &Argon2idHasher{Memory: 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 16}
	ok, needsRehash, err := longerSalt.Verify(context.Background(), "secret-pass", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || !needsRehash {
		t.Fatalf("ok=%v needsRehash=%v, want valid hash needing rehash", ok, needsRehash)
	}
}

func TestArgon2idRejectsUnsafeEncodedParameters(t *testing.T) {
	salt := "MDEyMzQ1Njc"
	key := "MDEyMzQ1Njc4OWFiY2RlZg"
	tests := map[string]string{
		"missing parameter":    "$argon2id$v=19$m=1024,t=1$" + salt + "$" + key,
		"duplicate parameter":  "$argon2id$v=19$m=1024,t=1,p=1,p=1$" + salt + "$" + key,
		"unknown parameter":    "$argon2id$v=19$m=1024,t=1,x=1$" + salt + "$" + key,
		"parallelism overflow": "$argon2id$v=19$m=1024,t=1,p=256$" + salt + "$" + key,
		"excessive memory":     "$argon2id$v=19$m=4294967295,t=1,p=1$" + salt + "$" + key,
		"excessive iterations": "$argon2id$v=19$m=1024,t=11,p=1$" + salt + "$" + key,
		"insufficient memory":  "$argon2id$v=19$m=8,t=1,p=2$" + salt + "$" + key,
		"short salt":           "$argon2id$v=19$m=1024,t=1,p=1$YWJjZA$" + key,
		"short key":            "$argon2id$v=19$m=1024,t=1,p=1$" + salt + "$YWJjZA",
		"oversized encoding":   strings.Repeat("x", maxEncodedHashLength+1),
	}
	h := &Argon2idHasher{Memory: 1024, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			if ok, needsRehash, err := h.Verify(context.Background(), "password", encoded); err == nil {
				t.Fatalf("Verify() = (%v, %v, nil), want an error", ok, needsRehash)
			}
		})
	}
}

func TestArgon2idRejectsUnsafeHasherConfiguration(t *testing.T) {
	h := &Argon2idHasher{
		Memory:      maxMemory + 1,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
	if _, err := h.Hash(context.Background(), "password"); err == nil {
		t.Fatal("Hash() error = nil, want unsafe configuration rejected")
	}
}
