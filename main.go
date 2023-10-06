package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/akamensky/argparse"
	"github.com/clcert/beacon-scripts-hsm/hsm"

	log "github.com/sirupsen/logrus"
)

func main() {
	fmt.Println("HSM Scripts for Signatures with PKCS#11 v1.5 - SHA512 and Random Number Generator")
	// Create new parser object
	parser := argparse.NewParser("app", "")

	// Create use action flag
	keygen := parser.NewCommand("keygen", "Generate a new keypair in the HSM")
	sign := parser.NewCommand("sign", "Sign a message with a key in the HSM")
	verify := parser.NewCommand("verify", "Verify a message with a key in the HSM")
	random := parser.NewCommand("random", "Generate 512 random bites in the HSM")
	pkExport := parser.NewCommand("export-key", "Export public key from the HSM")

	// Create parameter flags
	moduleLocationHSM := parser.String("l", "location", &argparse.Options{Required: false, Default: "", Help: "HSM Module Location"})
	pin := parser.String("p", "pin", &argparse.Options{Required: false, Default: "", Help: "HSM Partition PIN"})
	keyLabel := parser.String("k", "keylabel", &argparse.Options{Required: false, Default: "", Help: "HSM Key Label"})

	message := parser.String("m", "message", &argparse.Options{Required: false, Default: "", Help: "Message to sign"})
	signature := parser.String("s", "signature", &argparse.Options{Required: false, Default: "", Help: "Signature to verify"})

	// Parse input
	err := parser.Parse(os.Args)
	if err != nil {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}

	publicKeyLabel := *keyLabel + "-public"
	privateKeyLabel := *keyLabel + "-private"

	if keygen.Happened() {
		log.Infof("Generating keypair in HSM with key label '%s'", *keyLabel)
		hsm.Keygen(*moduleLocationHSM, *pin, *keyLabel)

	} else if sign.Happened() {
		log.Infof("Signing message '%s' with key label '%s'", *message, privateKeyLabel)
		signature := hsm.SignMessage(*moduleLocationHSM, *pin, privateKeyLabel, []byte(*message))
		strSign := hex.EncodeToString(signature)
		log.Infof("Signature: %s", strSign)

	} else if verify.Happened() {
		byteSign, err := hex.DecodeString(*signature)
		if err != nil {
			log.Errorf("Error decoding hex string: %v\n", err)
			return
		}
		log.Infof("Verifying signature with message '%s' and key label '%s'", *message, publicKeyLabel)
		hsm.VerifySignature(*moduleLocationHSM, *pin, publicKeyLabel, []byte(*message), byteSign)

	} else if random.Happened() {
		log.Infof("Generating random number")
		random := hsm.GenerateRandomBytes(*moduleLocationHSM, *pin, 64)
		strRandom := hex.EncodeToString(random)
		log.Infof("Random number: %s", strRandom)

	} else if pkExport.Happened() {
		log.Infof("Exporting public key with key label %s", publicKeyLabel)
		pkPem := hsm.ExportPublicKey(*moduleLocationHSM, *pin, publicKeyLabel)
		log.Infof("Public key: \n%s", pkPem)
	}
}
