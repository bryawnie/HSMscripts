package utils

import (
	"fmt"

	"github.com/clcert/beacon-scripts-hsm/db"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
)

func saveCertificate(moduleLocation, token_pin, publicKeyLabel string, certContent []byte) error {
	dbConn := db.ConnectDB()
	defer dbConn.Close()

	digest := sha3.Sum512(certContent)
	publicKey := ExtractPublicKeyHSM(moduleLocation, token_pin, publicKeyLabel, nil)
	if publicKey == nil {
		return fmt.Errorf("Error getting public key from HSM")
	}
	// Inserting certificate into DB
	// TODO:
	// 1. If certificate already exists, check if it has changed, if so, change
	//	  their status to 0 and insert new certificate with status 1.
	// 2. If certificate already exists and it hasn't changed, do nothing.
	// 3. Check obtention of public key from HSM.
	log.Infof("Inserting certificate into DB, values:\n name: %s\n public_key: %s\n certificate: %s\n certificate_id: %s\n", publicKeyLabel, publicKey, certContent, digest[:])
	// insertCertificateStatement := `INSERT INTO certificates (name, public_key, certificate, certificate_id, status) VALUES ($1, $2, $3, $4, $5);`
	// _, err := dbConn.Exec(insertCertificateStatement, publicKeyLabel, publicKey, certContent, digest[:], 1)
	// if err != nil {
	// 	log.Fatalf("Error inserting certificate into DB: %v", err)
	// 	return err
	// }
	return nil
}
