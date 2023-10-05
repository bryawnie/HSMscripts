package hsm

import (
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

func keygenHSM(p *pkcs11.Ctx, session pkcs11.SessionHandle, keyLabel string) {
	// Generate a key pair (example for RSA)
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, MODULUS_BITS),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{PUBLIC_EXPONENT}),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(keyLabel+"-public")),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(keyLabel+"-private")),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	}
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(SIGN_MECHANISM, nil)}
	_, _, err := p.GenerateKeyPair(session, mechanism, publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		log.Errorf("Failed to generate key pair: %s\n", err)
		return
	}

	log.Info("Key pair generated successfully!")
	log.Infof("Public key label: %s", keyLabel+"-public")
	log.Infof("Private key label: %s", keyLabel+"-private")
}
