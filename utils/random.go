package utils

import (
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

func RandomHSM(moduleLocation string, pin string) []byte {
	defaultValue := []byte("")
	p := pkcs11.New(moduleLocation)

	// ========= INIT MODULE ========== //
	if p == nil {
		log.Error("No HSM module available:", moduleLocation)
		return defaultValue
	}
	err := p.Initialize()
	if err != nil {
		log.Error("Failed to Initialize HSM")
		return defaultValue
	}
	defer p.Destroy()
	defer p.Finalize()

	// ========= GET SLOTS ========== //
	slots, err := getSlotList(p)
	if err != nil {
		log.Error(err.Error())
		return defaultValue
	}

	// ========= OPEN SESSION ========== //
	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Error("Failed to Open Session in HSM")
		return defaultValue
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		log.Error("Failed to Login in HSM")
		return defaultValue
	}
	defer p.Logout(session)

	// ========= GENERATE RANDOM BYTES ========== //
	randHSMBytesLength := 64 // 512 bits
	randHSMBytes, err := p.GenerateRandom(session, randHSMBytesLength)
	if err != nil {
		log.Error("Failed to Generate Random Bytes in HSM")
		return defaultValue
	}
	return randHSMBytes
}
