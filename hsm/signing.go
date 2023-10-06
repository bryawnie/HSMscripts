package hsm

import (
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

func signHSM(p *pkcs11.Ctx, session pkcs11.SessionHandle, keyLabel string, message, defaultSignature []byte) []byte {
	// find public key
	pvk, err := findHSMkeys(p, session, keyLabel, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		log.Error("Keys not found: ", err.Error())
		return defaultSignature
	}

	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(SIGN_MECHANISM, nil)}

	if e := p.SignInit(session, mechanism, pvk[0]); e != nil {
		log.Error("Failed to initialize signing tool with HSM. Error: " + e.Error())
		return defaultSignature
	}

	signature, err := p.Sign(session, message)
	if err != nil {
		log.Error("Failed at signing with HSM. Error: " + err.Error())
		return defaultSignature
	}

	return signature
}

func verifyHSM(p *pkcs11.Ctx, session pkcs11.SessionHandle, keyLabel string, message, signature []byte) bool {
	defaultValue := false
	// find public key
	pbk, err := findHSMkeys(p, session, keyLabel, pkcs11.CKO_PUBLIC_KEY)
	if err != nil {
		log.Error("Keys not found: ", err.Error())
		return defaultValue
	}
	mechanism := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(SIGN_MECHANISM, nil),
	}

	err = p.VerifyInit(session, mechanism, pbk[0])
	if err != nil {
		log.Fatal(err)
		return defaultValue
	}

	err = p.Verify(session, message, signature)
	if err == pkcs11.Error(pkcs11.CKR_SIGNATURE_INVALID) {
		log.Error("Signature is invalid")
		return defaultValue
	} else if err != nil {
		log.Fatalf("Failed to verify signature: %s\n", err)
		return defaultValue
	} else {
		log.Info("Signature is valid")
		return true
	}
}
