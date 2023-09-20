package utils

import (
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

func SignHSM(moduleLocation string, pin string, keyLabel string, message []byte) []byte {
	p := pkcs11.New(moduleLocation)

	// ========= INIT MODULE ========== //
	if p == nil {
		log.Error("No HSM module available:", moduleLocation)
		return zeroH(512)
	}
	err := p.Initialize()
	if err != nil {
		log.Error("Failed to Initialize HSM")
		return zeroH(512)
	}
	defer p.Destroy()
	defer p.Finalize()

	// ========= GET SLOTS ========== //
	slots, err := getSlotList(p)
	if err != nil {
		log.Error(err.Error())
		return zeroH(512)
	}

	// ========= OPEN SESSION ========== //
	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Error("Failed to Open Session in HSM")
		return zeroH(512)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		log.Error("Failed to Login in HSM")
		return zeroH(512)
	}
	defer p.Logout(session)

	// ========= FIND PRIVATE KEY ========== //
	pvk, err := findHSMkeys(p, session, keyLabel, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		log.Error(err.Error())
		return zeroH(512)
	}

	/*
		========= BEGIN SIGN =========
		SPEC: RSASSA-PKCS1-v1.5 signature using SHA-512 hash algorithm
	*/
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(signScheme, nil)}

	if e := p.SignInit(session, mechanism, pvk[0]); e != nil {
		log.Error("Failed to Initialize Signing with HSM: " + e.Error())
		return zeroH(512)
	}
	// Signing message
	signature, err := p.Sign(session, message)
	if err != nil {
		log.Error("Failed to Sign with HSM")
		return zeroH(512)
	}

	return signature
}

func VerifyHSM(moduleLocation string, pin string, keyLabel string, signature []byte, message []byte) bool {
	p := pkcs11.New(moduleLocation)

	// ========= INIT MODULE ========== //
	if p == nil {
		log.Error("No HSM module available:", moduleLocation)
		return false
	}
	err := p.Initialize()
	if err != nil {
		log.Error("Failed to Initialize HSM")
		return false
	}
	defer p.Destroy()
	defer p.Finalize()

	// ========= GET SLOTS ========== //
	slots, err := getSlotList(p)
	if err != nil {
		log.Error(err.Error())
		return false
	}

	// ========= OPEN SESSION ========== //
	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Error("Failed to Open Session in HSM")
		return false
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		log.Error("Failed to Login in HSM")
		return false
	}
	defer p.Logout(session)

	// ========= FIND PUBLIC KEY ========== //
	pbk, err := findHSMkeys(p, session, keyLabel, pkcs11.CKO_PUBLIC_KEY)
	if err != nil {
		log.Error("Keys not found: ", err.Error())
		return false
	}
	mechanism := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(signScheme, nil),
	}

	err = p.VerifyInit(session, mechanism, pbk[0])
	if err != nil {
		log.Fatal(err)
		return false
	}

	err = p.Verify(session, message, signature)
	if err == pkcs11.Error(pkcs11.CKR_SIGNATURE_INVALID) {
		return false
	} else if err != nil {
		log.Fatal(err)
		return false
	} else {
		return true
	}
}
