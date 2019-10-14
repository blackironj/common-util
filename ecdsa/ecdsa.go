package ecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"

	"github.com/blackironj/util/pem"
)

// TODO: write log

func Sign(msg []byte, skPem string, pass ...string) (string, error) {
	var privateKey *ecdsa.PrivateKey
	var err error

	if len(pass) != 0 {
		privateKey, err = GetECPrivateKeyFromPem(skPem, pass[0])
	} else {
		privateKey, err = GetECPrivateKeyFromPem(skPem)
	}

	if err != nil {
		return "", err
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, msg)
	if err != nil {
		return "", err
	}

	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)

	return string(signature), nil
}

func Verify(msg []byte, sigStr, certPem string) bool {
	publicKey, err := GetECPublicKeyFromPem(certPem)

	if err != nil {
		return false
	}
	sigBytes := []byte(sigStr)
	halfSigLen := len(sigBytes) / 2

	r := new(big.Int)
	r.SetBytes(sigBytes[:halfSigLen])

	s := new(big.Int)
	s.SetBytes(sigBytes[halfSigLen:])

	return ecdsa.Verify(publicKey, msg, r, s)
}

func GetECPublicKeyFromPem(pemData string) (*ecdsa.PublicKey, error) {
	cert, parseErr := pem.ParseX509Cert(pemData)

	if parseErr != nil {
		return nil, parseErr
	}

	publicKey := cert.PublicKey.(*ecdsa.PublicKey)

	return publicKey, nil
}

func GetECPrivateKeyFromPem(pemData string, pass ...string) (*ecdsa.PrivateKey, error) {
	data, decodeErr := pem.DecodePEM(pemData)

	if decodeErr != nil {
		return nil, decodeErr
	}

	var err error
	var privateKey *ecdsa.PrivateKey

	if x509.IsEncryptedPEMBlock(data) {
		if len(pass) == 0 {
			return nil, errors.New("need password")
		}

		var decryptedData []byte

		decryptedData, err = x509.DecryptPEMBlock(data, []byte(pass[0]))
		if err != nil {
			return nil, err
		}
		privateKey, err = x509.ParseECPrivateKey(decryptedData)
	} else {
		privateKey, err = x509.ParseECPrivateKey(data.Bytes)
	}

	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
