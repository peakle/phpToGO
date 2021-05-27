package phpToGO

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/pkg/errors"
)

func opensslVerify(data, sign []byte, publicKey string) error {
	PEMBlock, _ := pem.Decode([]byte(publicKey))
	if PEMBlock == nil {
		return errors.New("nil pem")
	}

	if PEMBlock.Type != "PUBLIC KEY" {
		return errors.New("Found wrong key type")
	}

	pubkey, err := x509.ParsePKIXPublicKey(PEMBlock.Bytes)
	if err != nil {
		return err
	}

	sum := sha1.Sum(data)

	err = rsa.VerifyPKCS1v15(pubkey.(*rsa.PublicKey), crypto.SHA1, sum[:], sign)
	if err != nil {
		return err
	}

	return nil
}

func opensslSign(data, privateKey []byte) ([]byte, error) {
	PEMBlock, _ := pem.Decode(privateKey)
	if PEMBlock == nil {
		return nil, errors.New("nil pem")
	}

	if !strings.Contains(PEMBlock.Type, "PRIVATE KEY") {
		return nil, errors.New("Found wrong key type")
	}

	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(PEMBlock.Bytes)
	if err != nil {
		return nil, err
	}

	sum := sha1.Sum(data)
	rng := rand.Reader

	return rsa.SignPKCS1v15(rng, rsaPrivateKey, crypto.SHA1, sum[:])
}
