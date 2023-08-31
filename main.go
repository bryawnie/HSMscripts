package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"

	"github.com/akamensky/argparse"
	"github.com/miekg/pkcs11"
	log "github.com/sirupsen/logrus"
)

var zeros = [512]byte{0x00}

func zeroH(numBytes int) []byte {
	return zeros[:numBytes]
}

func signHSM(moduleLocation string, pin string, keyLabel string, message []byte) []byte {
	p := pkcs11.New(moduleLocation)

	if p == nil {
		// No PKCS11 Module Available
		log.Error("No HSM module available: " + moduleLocation)
		return zeroH(512)
	}
	err := p.Initialize()
	if err != nil {
		log.Error("Failed to Initialize HSM Module")
		return zeroH(512)
	}
	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		log.Error("Failed to Get Slots in HSM")
		return zeroH(512)
	} else if len(slots) == 0 {
		log.Error("No Slots Available in HSM")
		return zeroH(512)
	}

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

	/*
		========= GET PVK OBJECTS FROM HSM =========
		This code is intended to be used to get the PVK object from the HSM
		instead of generating a new one.
	*/
	// template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel)}
	// if e := p.FindObjectsInit(session, template); e != nil {
	// 	log.Error("Failed to Initialize Finding Key in HSM")
	// 	return zeroH(512)
	// }
	// pvk, _, e := p.FindObjects(session, 2)
	// if e != nil {
	// 	log.Error("Failed to Find Key in HSM")
	// 	return zeroH(512)
	// } else if len(pvk) == 0 {
	// 	log.Error("No Key Found in HSM")
	// 	return zeroH(512)
	// }
	// if e := p.FindObjectsFinal(session); e != nil {
	// 	log.Error("Failed to Finalize Key Finding in HSM")
	// 	return zeroH(512)
	// }

	/*
		========= BEGIN KEY GENERATION =========
	*/
	var num uint16 = 4
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, num)
	if err != nil {
		log.Fatalf("binary.Write failed: %v", err)
	}
	pubID := buf.Bytes()

	buf = new(bytes.Buffer)
	num = 5
	err = binary.Write(buf, binary.LittleEndian, num)
	if err != nil {
		log.Fatalf("binary.Write failed: %v", err)
	}
	privID := buf.Bytes()

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "pub1"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, pubID),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "priv1"),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP_WITH_TRUSTED, false),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, privID),
	}

	pbk, pvk, err := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		log.Fatalf("failed to generate exportable keypair: %s\n", err)
	}

	/*
		========= END KEY GENERATION =========
	*/

	// Format public key for verification

	pr, err := p.GetAttributeValue(session, pbk, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		panic(err)
	}

	modulus := new(big.Int)
	modulus.SetBytes(pr[0].Value)
	bigExponent := new(big.Int)
	bigExponent.SetBytes(pr[1].Value)
	exponent := int(bigExponent.Uint64())

	rsaPub := &rsa.PublicKey{
		N: modulus,
		E: exponent,
	}

	// pubkeyPem := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(rsaPub)}))
	// log.Printf("  Public Key: \n%s\n", pubkeyPem)

	/*
		========= BEGIN SIGN =========
	*/

	// RSASSA-PKCS1-v1.5 signature using SHA-512 hash algorithm
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA512_RSA_PKCS, nil)}

	if e := p.SignInit(session, mechanism, pvk); e != nil {
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

	// Verify signature
	digest := sha512.Sum512(message)
	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA512, digest[:], signature)
	if err != nil {
		log.Printf("Failed verification. Retrying: %s", err)
		return zeroH(512)
	}
	log.Printf("Signature Verified!")

	return signature
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
	signHSM(*moduleLocationHSM, *pin, *keyLabel, message)
}
