package ecdsa

import (
	"testing"
)

const (
	testMsg      = "Hello ecdsa"

	testSkNoPass = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOMZidf+7NbS1irCitkVYlocIgPSyA/uj6PtmMfFFY5toAoGCCqGSM49
AwEHoUQDQgAEPXkQSql6psd1LLSQ9rKFE9gC+M6iqqVJQo6fkiWJGXOvP4LrO3v8
CjhvJ/JaPTRdujJCUcR6SSLfLV3yADUsZw==
-----END EC PRIVATE KEY-----`

	testSkPass = `-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2E3160053128D6D2FEEAE2FA40B1470D

k8H0D3hNLxgfvwLZ8MFgj9CMb507HLrEICfjfLrcJOfecMKBma/7h0FrxT5pXK4H
DQ17cdz7JqYw4Iub+Nj512hPRjFK3gktnnBUcovY10nIpRE95I43fcMAkdGuZmuJ
bK/MEj1zrA3F03Ptot4YsJabmd7ePC1JKzTKSm0ePcU=
-----END EC PRIVATE KEY-----`

	testCert = `-----BEGIN CERTIFICATE-----
MIIB4DCCAYWgAwIBAgIUWN3+jkg2Ef76/wdrcL5/8yZj/hUwCgYIKoZIzj0EAwIw
RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0xOTA4MDYwMTIwMjNaFw0yMDA4MDUw
MTIwMjNaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQ9eRBKqXqmx3UstJD2soUT2AL4zqKqpUlCjp+SJYkZc68/gus7e/wK
OG8n8lo9NF26MkJRxHpJIt8tXfIANSxno1MwUTAdBgNVHQ4EFgQUJwu/aMi6L6BT
uWqeonJpYhg44s8wHwYDVR0jBBgwFoAUJwu/aMi6L6BTuWqeonJpYhg44s8wDwYD
VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAr59ZZ7L3i5nihRkAC5jo
+70E8TeW7HPDOlvMa1Vu9EICIQCUDiXmhce9Y9QcnHoFSmrRsZwAfHvFfuM9G5AL
F6FZeg==
-----END CERTIFICATE-----`

	password = "1234"
)

func TestEcdsa_CaseOfNoPassword(t *testing.T) {
	signature, err := Sign(testMsg, testSkNoPass)
	if err != nil {
		t.Error(err)
	}

	success := Verify(testMsg, signature, testCert)
	if !success {
		t.Errorf("TestEcdsa_CaseOfNoPassword failed: want '%t', got '%t'", true, success)
	}
}

func TestEcdsa_CaseOfPassword(t *testing.T) {
	signature, err := Sign(testMsg, testSkPass, password)
	if err != nil {
		t.Error(err)
	}

	success := Verify(testMsg, signature, testCert)
	if !success {
		t.Errorf("TestEcdsa_CaseOfNoPassword failed: want '%t', got '%t'", true, success)
	}
}
