package utils

import (
	"bufio"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/clcert/beacon-scripts-hsm/db"
	"github.com/clcert/beacon-scripts-hsm/hsm"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
)

func requestConfirmation() bool {
	reader := bufio.NewReader(os.Stdin)
	log.Info("This operation add a new certificate in DB. Do you want to proceed? (y/N)")
	userInput, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading input:", err)
		return false
	}
	answer := strings.TrimSpace(userInput)
	lowerAnswer := strings.ToLower(answer)
	return lowerAnswer == "y" || lowerAnswer == "yes"
}

func existsCertificateInDB(id string) bool {
	dbConn := db.ConnectDB()
	defer dbConn.Close()

	var certificateID string
	err := dbConn.QueryRow("SELECT certificate_id FROM certificates WHERE certificate_id=$1", id).Scan(&certificateID)
	switch err {
	case sql.ErrNoRows:
		return false
	case nil:
		return true
	default:
		log.Errorf("Error checking if certificate exists in DB: %v", err)
		return true
	}
}

func SaveCertificate(moduleLocation, token_pin, keyLabel string, certPath string) {
	dbConn := db.ConnectDB()
	defer dbConn.Close()

	// Read the content of the file
	certContent, err := os.ReadFile(certPath)
	if err != nil {
		log.Fatalf("error reading file: %v", err)
		return
	}

	digest := sha3.Sum512(certContent)
	hashedCert := hex.EncodeToString(digest[:])
	publicKey := hsm.ExportPublicKey(moduleLocation, token_pin, keyLabel)
	if string(publicKey) == "" {
		log.Errorf("error getting public key from HSM")
		return
	}

	// Check if certificate already exists in DB
	if existsCertificateInDB(hashedCert) {
		log.Errorf("Certificate already exists in DB")
		return
	}

	// Request confirmation
	log.Info("The following certificate will be inserted into DB:")
	log.Infof("Name: %s", keyLabel)
	log.Infof("Public Key: %s\n", publicKey)
	log.Infof("Certificate: %s\n", certContent)
	log.Infof("Certificate ID: %s\n", hashedCert)
	confirmation := requestConfirmation()
	if !confirmation {
		log.Info("Operation cancelled")
		return
	}

	// To be considered: since certificates are searched by their name, status is actually not needed.
	insertCertificateStatement := `INSERT INTO certificates (name, public_key, certificate, certificate_id, status) VALUES ($1, $2, $3, $4, $5);`
	_, err = dbConn.Exec(insertCertificateStatement, keyLabel, publicKey, certContent, digest[:], 1)
	if err != nil {
		log.Fatalf("Error inserting certificate into DB: %v", err)
		return
	}
}
