package hsm

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"

	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

func exportPublicKeyHSM(p *pkcs11.Ctx, session pkcs11.SessionHandle, keyLabel string, defaultValue []byte) []byte {
	// find public key
	pbk, err := findHSMkeys(p, session, keyLabel, pkcs11.CKO_PUBLIC_KEY)
	if err != nil {
		log.Errorf("Key %s not found: %s", keyLabel, err.Error())
		return defaultValue
	}

	publicKeyHandle := pbk[0]
	// Get the public key data
	publicKeyBytes, err := p.GetAttributeValue(session, publicKeyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		log.Fatalf("Failed to get public key attributes: %v", err)
		return defaultValue
	}
	// Create an RSA public key
	rsaPublicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(publicKeyBytes[0].Value),
		E: PUBLIC_EXPONENT,
	}

	// Convert the RSA public key to a DER-encoded format
	derBytes, err := x509.MarshalPKIXPublicKey(rsaPublicKey)
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
	}

	// Create a PEM block for the RSA public key
	publicKeyPEMBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derBytes,
	}

	// Encode the PEM block to a string
	publicKeyPEM := pem.EncodeToMemory(publicKeyPEMBlock)

	return publicKeyPEM

}
