package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"flag"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

func main() {
	mnemonicPtr := flag.String("m", "", "Specify the mnemonic string")
	startIndexPtr := flag.Uint("f", 0, "Specify the first index (integer) of HD address, default:0")
	endIndexPtr := flag.Uint("t", 0, "Specify the last index (integer) of HD address")
	showHelp := flag.Bool("h", false, "Show usage information")

	var endIndex uint

	flag.Parse()

	if *showHelp || *mnemonicPtr == "" {
		flag.Usage()
		return
	}

	if *endIndexPtr < *startIndexPtr {
		endIndex = *startIndexPtr
	} else {
		endIndex = *endIndexPtr
	}

	seed := bip39.NewSeed(*mnemonicPtr, "")
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

	for i := *startIndexPtr; i <= endIndex; i++ {
		indexKey, err := childKey.NewChildKey(uint32(i))
		if err != nil {
			fmt.Println(err, "000000")
			return
		}

		// Ugly fix of the EOF issue when read from a bytes reader
		var privateKey *ecdsa.PrivateKey
		for j := 0; j < 100; j++ {
			reader := bytes.NewReader(indexKey.Key)
			privateKey, err = ecdsa.GenerateKey(crypto.S256(), reader)
			if err == nil {
				break
			}
		}
		// reader := bytes.NewReader(indexKey.Key)
		// privateKey, err := ecdsa.GenerateKey(crypto.S256(), reader)
		if err != nil {
			fmt.Println(err, "100000")
			return
		}

		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			fmt.Println("error casting public key to ECDSA")
			return
		}

		fmt.Println("BIP32 path:", "m/44'/60'/0'/0/", i)

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
}
