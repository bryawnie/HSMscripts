package hsm

import (
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

func generateRandomBytes(p *pkcs11.Ctx, session pkcs11.SessionHandle, nBytes int, defaultValue []byte) []byte {
	randHSMBytes, err := p.GenerateRandom(session, nBytes)
	if err != nil {
		log.Error("Failed generating random bytes in HSM. Error: " + err.Error())
		return defaultValue
	}
	return randHSMBytes
}
