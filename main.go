package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/akamensky/argparse"
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

var zeros = [512]byte{0x00}
const (
	// also pkcs11.CKM_ECDSA
	signScheme = pkcs11.CKM_SHA512_RSA_PKCS
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

func signHSM(moduleLocation string, pin string, keyLabel string, message []byte) []byte {
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
	log.Infof("Signature: %x", signature)

	return signature
}

func verifyHSM(moduleLocation string, pin string, keyLabel string, signature []byte, message []byte) bool {
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

	// ========= FIND PRIVATE KEY ========== //
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
		fmt.Println("Signature is invalid.")
		return false
	} else if err != nil {
		log.Fatal(err)
		return false
	} else {
		fmt.Println("Signature is valid.")
		return true
	}
}

func main() {
	// Create new parser object
	parser := argparse.NewParser("SoftHSM Signing Script with PKCS#11 v1.5 - SHA512", "")
	// Create flags
	moduleLocationHSM := parser.String("m", "module", &argparse.Options{Required: false, Default: "", Help: "HSM Module Location"})
	pin := parser.String("p", "pin", &argparse.Options{Required: false, Default: "", Help: "HSM Partition PIN"})
	keyLabel := parser.String("k", "keylabel", &argparse.Options{Required: false, Default: "", Help: "HSM Key Label"})
	// Parse input
	err := parser.Parse(os.Args)
	if err != nil {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}

	message := []byte("foo")
	signature := signHSM(*moduleLocationHSM, *pin, *keyLabel, message)
	verifyHSM(*moduleLocationHSM, *pin, *keyLabel, signature, message)
}
