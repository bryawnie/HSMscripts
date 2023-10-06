package hsm

import (
	"errors"

	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

type Params struct {
	action, randBytesLength          int
	moduleLocation, pin, keyLabel    string
	message, signature, defaultValue []byte
}

const (
	HSM_SIGN      = 1
	HSM_VERIFY    = 2
	HSM_KEYGEN    = 3
	HSM_EXPORT_PK = 4
	HSM_RNG       = 5

	MODULUS_BITS    = 4096
	PUBLIC_EXPONENT = 3
	// RSASSA-PKCS1-v1.5 signature using SHA-512 hash algorithm
	SIGN_MECHANISM   = pkcs11.CKM_SHA512_RSA_PKCS
	KEYGEN_MECHANISM = pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN
)

func SignMessage(moduleLocation, pin, keyLabel string, message []byte) []byte {
	params := Params{
		action:         HSM_SIGN,
		moduleLocation: moduleLocation,
		pin:            pin,
		keyLabel:       keyLabel,
		message:        message,
		defaultValue:   []byte{},
	}
	return proxyHSM(params)
}

func VerifySignature(moduleLocation, pin, keyLabel string, message, signature []byte) bool {
	params := Params{
		action:         HSM_VERIFY,
		moduleLocation: moduleLocation,
		pin:            pin,
		keyLabel:       keyLabel,
		message:        message,
		signature:      signature,
		defaultValue:   []byte{},
	}
	return string(proxyHSM(params)) == "1"
}

func Keygen(moduleLocation, pin, keyLabel string) {
	params := Params{
		action:         HSM_KEYGEN,
		moduleLocation: moduleLocation,
		pin:            pin,
		keyLabel:       keyLabel,
		defaultValue:   []byte{},
	}
	proxyHSM(params)
}

func ExportPublicKey(moduleLocationHSM string, pin string, keyLabel string) []byte {
	return proxyHSM(Params{
		action:         HSM_EXPORT_PK,
		moduleLocation: moduleLocationHSM,
		pin:            pin,
		keyLabel:       keyLabel,
		defaultValue:   []byte{},
	})
}

func GenerateRandomBytes(moduleLocationHSM string, pin string, randBytesLength int) []byte {
	return proxyHSM(Params{
		action:          HSM_RNG,
		moduleLocation:  moduleLocationHSM,
		pin:             pin,
		randBytesLength: randBytesLength,
		defaultValue:    []byte{},
	})
}

func proxyHSM(params Params) []byte {
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
	case HSM_VERIFY:
		if verifyHSM(p, session, params.keyLabel, params.message, params.signature) {
			return []byte("1")
		} else {
			return []byte("0")
		}
	case HSM_KEYGEN:
		keygenHSM(p, session, params.keyLabel)
		return []byte{}
	case HSM_EXPORT_PK:
		return exportPublicKeyHSM(p, session, params.keyLabel, params.defaultValue)
	case HSM_RNG:
		return generateRandomBytes(p, session, params.randBytesLength, params.defaultValue)
	default:
		return params.defaultValue
	}
}

func findHSMkeys(p *pkcs11.Ctx, session pkcs11.SessionHandle, keyLabel string, keyClass interface{}) ([]pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, keyClass),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
	}

	if e := p.FindObjectsInit(session, template); e != nil {
		return nil, errors.New("failed to initialize finding key in HSM: " + e.Error())
	}
	pvk, _, e := p.FindObjects(session, 1)
	if e != nil {
		return nil, errors.New("failed to find key in HSM: " + e.Error())
	} else if len(pvk) == 0 {
		return nil, errors.New("no key found in HSM")
	}
	if e := p.FindObjectsFinal(session); e != nil {
		return nil, errors.New("failed to finalize key finding in HSM: " + e.Error())
	}

	return pvk, nil
}
