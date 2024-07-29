package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"os"
	 "strings"

	"golang.org/x/crypto/ssh"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// EncryptKeyAndWriteToFile takes a private ed25519 key, a password and a filepath string and writes the encrypted key in OpenSSH format to that location.
func EncryptKeyAndWriteToFile(privkey ed25519.PrivateKey, password string, outputLocation string, comment string) {
	// encrypt private key into OpenSSH format
	pwBytes := []byte(password)
	encryptedPEM, err := ssh.MarshalPrivateKeyWithPassphrase(privkey, comment, pwBytes)
	if err != nil {
		panic(fmt.Sprintf("encrypt - %v", err))
	}

	// check if file exists already, warn user that it will be deleted (technically truncated). in production maybe require explicit confirmation before doing this
	_, err = os.Stat(outputLocation)
	if err == nil { // this is useful for automated testing, change in production
		fmt.Printf("Warning: There already exists a keyfile at %v. It will be overwritten!\n", outputLocation)
	}

	// write pem to file
	//		open file
	file, err := os.Create(outputLocation)
    if err != nil {
        panic(fmt.Sprintf("Failed to create key file: %v\n", err))
    }
    defer file.Close()

    //		write to file
	err = pem.Encode(file, encryptedPEM)
	if err != nil {
		panic(fmt.Sprintf("Failed to write PEM key to file: %v\n", err))
	}

	// set file permission to 600 (otherwise tools like ssh-keygen will complain that permissions are too open and refuse to do anything)
	err = os.Chmod(outputLocation, 0600)
	if err != nil {
		panic(fmt.Sprintf("Failed to set private key file permission: %v", err))
	}

}

// PubKeyToNodeID takes a PubKey and returns the human-readable node ID (12D3Koo...)
func PubKeyToNodeID(pubKeyObject crypto.PubKey) (string, error) {
	peerID, err := peer.IDFromPublicKey(pubKeyObject)
	if err != nil {
		return "", fmt.Errorf("Failed to convert PubKey to peerID: %v", err)
	}

	return peerID.String(), nil
}

func main() {
	// define what to mine for, this string should be at the end of the created libp2p node ID (should be fast for strings smaller than 5 chars)
	suffixOfInterest := "ra"
	
	pw := "supersecretrapw"
	comment := "gophy key"

	for {
		// generate ed25519 key
		_, ed25519Priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}

		// convert ed25519 key to libp2p compatiblbe ed25519 key
		var priv crypto.PrivKey
		priv, err = crypto.UnmarshalEd25519PrivateKey(ed25519Priv)
	    if err != nil {
	        panic(err)
	    }

		 // derive libp2p pubkey
		var pub crypto.PubKey
	    pub = priv.GetPublic()

		// derive libp2p nodeID from pubkey
		nodeIDString, err := PubKeyToNodeID(pub)
		if err != nil {
			panic(err)
		}

		// determine whether created identity ends with suffixOfInterest
		lastFourCharsOfNodeIDLowercase := strings.ToLower(nodeIDString[len(nodeIDString)-len(suffixOfInterest):])
		if lastFourCharsOfNodeIDLowercase == strings.ToLower(suffixOfInterest) {
			// permanently store identity file encrypted with chosen password
			EncryptKeyAndWriteToFile(ed25519Priv, pw, "./raprivkey.key", comment)
			fmt.Printf("Success! Found node ID: %v\n", nodeIDString)
			
			// also persists the nodeID string as nodeid.txt
			file, err := os.OpenFile("./nodeid.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		    	if err != nil {
		        	panic(err)
		    	}
		    	defer file.Close()
		    	_, err = file.WriteString(nodeIDString)
		    	if err != nil {
		        	panic(err)
    			}
			
			break
		} else {
			//fmt.Printf("Does not match requirements: %v\n", nodeIDString)
		}
	}

	// you can verify that it was correctly encrypted with pw and stored in OpenSSH key format with: "ssh-keygen -y -f ./privkey.key"

}
