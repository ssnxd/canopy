package twofactor

import (
	"testing"
	"time"
)

func TestTOTPGenerateAndValidate(t *testing.T) {
	totp := NewTOTP()
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	if !totp.Validate(secret, code, now) {
		t.Fatal("valid code was rejected")
	}
}

func TestTOTPRejectsWrongCode(t *testing.T) {
	totp := NewTOTP()
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if totp.Validate(secret, "000000", time.Unix(0, 0)) && totp.Validate(secret, "111111", time.Unix(0, 0)) {
		t.Fatal("two different wrong codes both passed; validation is broken")
	}
	if totp.Validate(secret, "12345", time.Now()) {
		t.Fatal("a code of the wrong length passed")
	}
}

func TestTOTPToleratesOneStepSkew(t *testing.T) {
	totp := NewTOTP()
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	code, err := totp.GenerateCode(secret, base.Add(-30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !totp.Validate(secret, code, base) {
		t.Fatal("code from the previous period was rejected despite skew")
	}
}
