package utils

import (
	"fmt"

	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

func KeygenHSM(moduleLocation string, pin string, keyLabel string) {
	p := pkcs11.New(moduleLocation)

	// ========= INIT MODULE ========== //
	if p == nil {
		log.Error("No HSM module available:", moduleLocation)
		return
	}
	err := p.Initialize()
	if err != nil {
		log.Error("Failed to Initialize HSM")
		return
	}
	defer p.Destroy()
	defer p.Finalize()

	// ========= GET SLOTS ========== //
	slots, err := getSlotList(p)
	if err != nil {
		log.Error(err.Error())
		return
	}

	// ========= OPEN SESSION ========== //
	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Error("Failed to Open Session in HSM")
		return
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		log.Error("Failed to Login in HSM")
		return
	}
	defer p.Logout(session)

	// Generate a key pair (example for RSA)
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 4096),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{3}),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(keyLabel + "-public")),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(keyLabel + "-private")),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	}
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(keygenMechanism, nil)}
	_, _, err = p.GenerateKeyPair(session, mechanism, publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		fmt.Printf("Failed to generate key pair: %s\n", err)
		return
	}

	fmt.Println("Key pair generated successfully!")
}
