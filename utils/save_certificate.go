package utils

import (
	"encoding/hex"
	"os"

	"github.com/clcert/beacon-scripts-hsm/db"
	"github.com/clcert/beacon-scripts-hsm/hsm"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
)

func SaveCertificate(moduleLocation, token_pin, publicKeyLabel string, certPath string) {
	dbConn := db.ConnectDB()
	defer dbConn.Close()

	// Read the content of the file
	certContent, err := os.ReadFile(certPath)
	if err != nil {
		log.Fatalf("error reading file: %v", err)
	}

	digest := sha3.Sum512(certContent)
	hashedCert := hex.EncodeToString(digest[:])
	// Obtaining public key from HSM
	publicKey := hsm.ExportPublicKey(moduleLocation, token_pin, publicKeyLabel)
	if string(publicKey) == "" {
		log.Errorf("error getting public key from HSM")
	}
	// Inserting certificate into DB
	// TODO:
	// 1. If certificate already exists, check if it has changed, if so, change
	//	  their status to 0 and insert new certificate with status 1.
	// 2. If certificate already exists and it hasn't changed, do nothing.
	// 3. Check obtention of public key from HSM.
	log.Infof("Inserting certificate into DB, values:\n name: %s\n public_key: %s\n certificate: %s\n certificate_id: %s\n", publicKeyLabel, publicKey, certContent, hashedCert)
	// insertCertificateStatement := `INSERT INTO certificates (name, public_key, certificate, certificate_id, status) VALUES ($1, $2, $3, $4, $5);`
	// _, err := dbConn.Exec(insertCertificateStatement, publicKeyLabel, publicKey, certContent, digest[:], 1)
	// if err != nil {
	// 	log.Fatalf("Error inserting certificate into DB: %v", err)
	// 	return err
	// }
}
