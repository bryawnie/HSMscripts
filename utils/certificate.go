package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"

	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

func ExtractCertificateHSM(moduleLocation string, pin string, keyLabel string) bool {
	defaultResponse := false
	p := pkcs11.New(moduleLocation)

	// ========= INIT MODULE ========== //
	if p == nil {
		log.Error("No HSM module available:", moduleLocation)
		return defaultResponse
	}
	err := p.Initialize()
	if err != nil {
		log.Error("Failed to Initialize HSM")
		return defaultResponse
	}
	defer p.Destroy()
	defer p.Finalize()

	// ========= GET SLOTS ========== //
	slots, err := getSlotList(p)
	if err != nil {
		log.Error(err.Error())
		return defaultResponse
	}

	// ========= OPEN SESSION ========== //
	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Error("Failed to Open Session in HSM")
		return defaultResponse
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		log.Error("Failed to Login in HSM")
		return defaultResponse
	}
	defer p.Logout(session)

	// ========= FIND PUBLIC KEY ========== //
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
	}

	if e := p.FindObjectsInit(session, template); e != nil {
		return defaultResponse
	}
	pbk, _, e := p.FindObjects(session, 1)
	if e != nil {
		return defaultResponse
	} else if len(pbk) == 0 {
		return defaultResponse
	}
	if e := p.FindObjectsFinal(session); e != nil {
		return defaultResponse
	}
	if err != nil {
		log.Error("Keys not found: ", err.Error())
		return false
	}

	publicKeyHandle := pbk[0]
	// Get the public key data
	publicKeyBytes, err := p.GetAttributeValue(session, publicKeyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		log.Fatalf("Failed to get public key attributes: %v", err)
		return false
	}
	// Create an RSA public key
	rsaPublicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(publicKeyBytes[0].Value),
		E: 3, // The public exponent used in most RSA keys
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

	log.Infof("Public Key %s (PEM):\n%s\n", keyLabel, string(publicKeyPEM))

	return true
}
