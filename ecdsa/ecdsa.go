package ecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"strings"
)

// TODO: write log

func Sign(msg []byte, skPem string, pass ...string) (string, error) {
	var privateKey *ecdsa.PrivateKey
	var err error

	if len(pass) != 0 {
		privateKey, err = GetPrivateKeyFromPem(skPem, pass[0])
	} else {
		privateKey, err = GetPrivateKeyFromPem(skPem)
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
	publicKey, err := GetPublicKeyFromPem(certPem)

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

func DecodePem(pemData string) (*pem.Block, error) {
	r := strings.NewReader(pemData)

	pemBytes, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	data, _ := pem.Decode(pemBytes)

	return data, nil
}

func GetPublicKeyFromPem(pemData string) (*ecdsa.PublicKey, error) {
	data, decodeErr := DecodePem(pemData)

	if decodeErr != nil {
		return nil, decodeErr
	}

	var cert *x509.Certificate
	cert, parseErr := x509.ParseCertificate(data.Bytes)

	if parseErr != nil {
		return nil, parseErr
	}

	publicKey := cert.PublicKey.(*ecdsa.PublicKey)

	return publicKey, nil
}

func GetPrivateKeyFromPem(pemData string, pass ...string) (*ecdsa.PrivateKey, error) {
	data, decodeErr := DecodePem(pemData)

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
