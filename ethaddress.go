package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

func main() {
	// mnemonic := "atom favorite rely funny disorder vast echo spin segment market cat hood"
	// Get user input for the mnemonic
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter your mnemonic: ")
	mnemonic, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading input:", err)
		return
	}

	// clean up the mnemonic string
	mnemonic = strings.TrimSpace(mnemonic)

	seed := bip39.NewSeed(mnemonic, "")

	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Derive key for m/44'/60'/0'/0/0 path
	childKey, err := masterKey.NewChildKey(bip32.FirstHardenedChild + 44)
	if err != nil {
		fmt.Println(err)
		return
	}
	childKey, err = childKey.NewChildKey(bip32.FirstHardenedChild + 60)
	if err != nil {
		fmt.Println(err)
		return
	}
	childKey, err = childKey.NewChildKey(bip32.FirstHardenedChild)
	if err != nil {
		fmt.Println(err)
		return
	}
	childKey, err = childKey.NewChildKey(0)
	if err != nil {
		fmt.Println(err)
		return
	}
	childKey, err = childKey.NewChildKey(0)
	if err != nil {
		fmt.Println(err)
		return
	}

	privateKey, err := ecdsa.GenerateKey(crypto.S256(), bytes.NewReader(childKey.Key))
	if err != nil {
		fmt.Println(err)
		return
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("error casting public key to ECDSA")
		return
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	fmt.Println("Ethereum address:", address)

	// // create a new keystore and add the key to it
	// ks := keystore.NewKeyStore(".", keystore.StandardScryptN, keystore.StandardScryptP)
	// newAcc, err := ks.ImportECDSA(privateKey, "")
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// fmt.Println("Keystore path:", ks.JoinPath(newAcc.Address.Hex()))

	// encode private key to hex string
	hexPrivateKey := hex.EncodeToString(crypto.FromECDSA(privateKey))
	fmt.Println("Hex private key:", hexPrivateKey)

	// encode public key to hex string
	hexPublicKey := hexutil.Encode(crypto.FromECDSAPub(publicKeyECDSA)[1:])
	fmt.Println("Hex public key:", hexPublicKey)
}
