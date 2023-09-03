package utils

import (
	"errors"

	"github.com/miekg/pkcs11"
)

var zeros = [512]byte{0x00}

const (
	// also pkcs11.CKM_ECDSA
	signScheme = pkcs11.CKM_SHA512_RSA_PKCS
	keygenMechanism = pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN
)

func zeroH(numBytes int) []byte {
	return zeros[:numBytes]
}

func getSlotList(p *pkcs11.Ctx) ([]uint, error) {
	slots, err := p.GetSlotList(true)
	if err != nil {
		return nil, errors.New("failed to get slots in HSM: " + err.Error())
	} else if len(slots) == 0 {
		return nil, errors.New("no slots available in HSM")
	}
	return slots, nil
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
