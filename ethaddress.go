package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

func main() {
	var mnemonic, indexStr string
	var index uint64
	var err error

	// args: memonic and path string
	args := os.Args[1:]
	if len(args) == 2 {
		mnemonic = args[0]
		indexStr = args[1]

	} else {
		// mnemonic := "atom favorite rely funny disorder vast echo spin segment market cat hood"
		// Get user input for the mnemonic
		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Enter your mnemonic: ")
		mnemonic, err = reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading mnemonic:", err)
			return

		}
		fmt.Print("Enter BIP32 index(m/44'/60'/0'/0/index): ")
		indexStr, err = reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading index:", err)
			return
		}
	}

	// clean up the mnemonic string
	mnemonic = strings.TrimSpace(mnemonic)
	indexStr = strings.TrimSpace(indexStr)

	index, err = strconv.ParseUint(indexStr, 10, 32)
	if err != nil {
		fmt.Println("The index need to be an uint number", indexStr)
		return
	}

	fmt.Println(mnemonic, indexStr, index)

	seed := bip39.NewSeed(mnemonic, "")
	masterKey, err := bip32.NewMasterKey(seed)

	if err != nil {
		fmt.Println(err)
		return
	}

	// Derive key for m/44'/60'/0'/0/index path
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
	childKey, err = childKey.NewChildKey(uint32(index))
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

	fmt.Println("BIP32 path:", "m/44'/60'/0'/0/", index)
}
