package helper

import (
	"testing"
)

func TestTLSVerifySkip(t *testing.T) {

	_, err := Get("https://self-signed.badssl.com/")

	if err == nil {
		t.Error()
	}

	DisableTlsVerification()

	_, err = Get("https://self-signed.badssl.com/")

	if err != nil {
		t.Error()
	}

}
