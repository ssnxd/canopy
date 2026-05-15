package password

import (
	"context"
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
