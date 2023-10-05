package utils

import (
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

type Params struct {
	action, randBytesLength       int
	moduleLocation, pin, keyLabel string
	message, defaultValue         []byte
}

const (
	HSM_SIGN      = 1
	HSM_RNG       = 2
	HSM_EXPORT_PK = 3

	PUBLIC_EXPONENT = 3
)

func ProxyHSM(params Params) []byte {
	p := pkcs11.New(params.moduleLocation)

	// ========= INIT MODULE ========== //
	if p == nil {
		log.Error("Error: no HSM module available at " + params.moduleLocation)
		return params.defaultValue
	}
	err := p.Initialize()
	if err != nil {
		log.Error("Failed initializing HSM module. Error: " + err.Error())
		return params.defaultValue
	}
	defer p.Destroy()
	defer p.Finalize()

	// ========= GET SLOTS ========== //
	slots, err := p.GetSlotList(true)
	if err != nil {
		log.Error("Failed getting slots in HSM. Error: " + err.Error())
		return params.defaultValue
	} else if len(slots) == 0 {
		log.Error("No slots available in HSM.")
		return params.defaultValue
	}

	sessionSlot := slots[0]
	log.Info("Opening session in HSM.")
	session, err := p.OpenSession(sessionSlot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Error("Failed opening session in HSM. Error: " + err.Error())
		return params.defaultValue
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, params.pin)
	if err != nil {
		log.Error("Failed to login in HSM. Error: " + err.Error())
		return params.defaultValue
	}
	defer p.Logout(session)

	switch params.action {
	case HSM_SIGN:
		return signHSM(p, session, params.keyLabel, params.message, params.defaultValue)
	case HSM_RNG:
		randHSMBytes, err := p.GenerateRandom(session, params.randBytesLength)
		if err != nil {
			log.Error("Failed generating random bytes in HSM. Error: " + err.Error())
			return params.defaultValue
		}
		return randHSMBytes
	case HSM_EXPORT_PK:
		return exportPublicKeyHSM(p, session, params.keyLabel, params.defaultValue)
	default:
		return params.defaultValue
	}
}

func signHSM(p *pkcs11.Ctx, session pkcs11.SessionHandle, keyLabel string, message, defaultSignature []byte) []byte {
	// ========= FIND PRIVATE KEY REF ========== //
	privKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
	}

	if e := p.FindObjectsInit(session, privKeyTemplate); e != nil {
		log.Error("Failed initializing 'finding key' in HSM. Error: " + e.Error())
		return defaultSignature
	}
	pvk, _, e := p.FindObjects(session, 1)
	if e != nil {
		log.Error("Failed at finding key in HSM. Error: " + e.Error())
		return defaultSignature
	} else if len(pvk) == 0 {
		log.Error("No keys matching the template were found in HSM.")
		return defaultSignature
	}
	if e := p.FindObjectsFinal(session); e != nil {
		log.Error("Failed at finalizing 'finding key' in HSM. Error: " + e.Error())
		return defaultSignature
	}

	/*
		========= SIGN message =========
		SPEC: RSASSA-PKCS1-v1.5 signature using SHA-512 hash algorithm
	*/
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA512_RSA_PKCS, nil)}

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
