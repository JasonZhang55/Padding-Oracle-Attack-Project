package main

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

func main()  {

	mode := os.Args[1]
	inputSet := flag.NewFlagSet("", flag.ExitOnError)
	key := inputSet.String("k", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "32-byte key in hexadecimal")
	input := inputSet.String("i", "", "input file")
	output := inputSet.String("o", "", "output file")
	inputSet.Parse(os.Args[2:])

	keyByte := []byte(*key)
	//fmt.Println("length of keybyte",len(keyByte))
	//fmt.Println("key:", *key)
	//fmt.Println("input:", *input)
	//fmt.Println(len(os.Args))

	if len(os.Args) < 8 {
		fmt.Println("Operation mode (encrypt, decrypt), key, input and output file must be included.")
		flag.PrintDefaults()
	}

	// encrypt
	if mode == "encrypt" {
		message := readFile(*input)
		keyEnc := keyByte[:16]
		keyMac := keyByte[16:]
		tagT := computeHmac([]byte(message), keyMac)
		messageP := append([]byte(message), tagT...)
		//fmt.Printf("%d\n", len(messageP))
		messagePP := padding(messageP)
		//fmt.Printf("%x\n", messagePP)
		cipherText, _ := encryptAesCBC(messagePP, keyEnc)
		//fmt.Printf("%x\n", cipherText)
		writeFile(cipherText, *output)
	} else if mode == "decrypt"{
		//decrypt
		cipherText := readFile(*input)
		keyEnc := keyByte[:16]
		keyMac := keyByte[16:]
		plainTextT, err:= decryptAesCBC([]byte(cipherText), keyEnc)
		if err != nil {
			fmt.Println(err)
		}
		plainText := plainTextT[:len(plainTextT) - 32]
		tagT2 := plainTextT[len(plainTextT) - 32:]
		tmp := computeHmac(plainText, keyMac)
		if string(tagT2) != string(tmp) {
			fmt.Println("INVALID MAC")
			return
		}
		writeFile(plainText, *output)
		//fmt.Printf("%x\n", plainText)
	} else {
		fmt.Println("encrypt and decrypt only")
		os.Exit(1)
	}
	return
}

func readFile(path string) string {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Print(err)
	}
	return string(content)
}

func writeFile(content []byte, path string)  {
	err := ioutil.WriteFile(path, content, 0644)
	if err != nil {
		panic(err)
	}
}

func computeHmac(message []byte, key []byte) []byte {
	k_ipad := make([]byte, 16)
	k_opad := make([]byte, 16)
	for i := 0; i < 16; i++ {
		k_ipad[i] = key[i] ^ 0x36
		k_opad[i] = key[i] ^ 0x5c
	}
	hash := sha256.New()
	hash.Write([]byte(k_ipad))
	hash.Write([]byte(message))
	inner := hash.Sum(nil)
	hash2 := sha256.New()
	hash2.Write([]byte(k_opad))
	hash2.Write([]byte(inner))
	outer := hash2.Sum(nil)
	return outer

}

func padding(message []byte) []byte {
	n := len(message) % 16
	if n == 0 {
		pad := make([]byte, 16)
		for i:=0; i < 16; i++ {
			pad[i] = 0x10
		}
		message = append(message, pad...)
	} else {
		pad := make([]byte, 16 - n)
		for i:=0; i < 16 - n; i++ {
			pad[i] = byte(16-n)
		}
		message = append(message, pad...)
	}
	return message
}

func generateRandBytes(n int) ([]byte, error) {
	randBytes := make([]byte, 16)
	_, err := rand.Read(randBytes)
	if err != nil {
		return nil, err
	}
	return randBytes, nil
}

func encryptAesCBC(message []byte, key []byte) ([]byte, error) {
	IV, _ := generateRandBytes(16)
	encrypt, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := aes.BlockSize
	//lastCipherText := IV[:]
	lastCipherText := make([]byte, len(IV))
	copy(lastCipherText, IV)
	finalCipherText := make([]byte, 0)
	preCipherText := make([]byte, bs)
	count := len(message) / bs
	for i := 0; i < count; i++ {
		for j := 0; j < bs; j++ {
			preCipherText[j] = message[i*bs+j] ^ lastCipherText[j]
		}
		encrypt.Encrypt(lastCipherText, preCipherText)
		finalCipherText = append(finalCipherText, lastCipherText...)
	}
	finalCipherText = append(IV, finalCipherText...)
	return finalCipherText, err
}

func decryptAesCBC(cipherText []byte, key []byte) ([]byte, error) {
	// decrypt the cipherText
	IV := cipherText[:16]
	cipherText = cipherText[16:]
	decrypt, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := aes.BlockSize
	plainText := make([]byte, len(cipherText))
	prePlainText := make([]byte, bs)
	//finalPlainText := make([]byte, 0)
	count := len(cipherText) / bs
	for i := count - 1; i > 0; i-- {
		decrypt.Decrypt(prePlainText, cipherText[i*bs:i*bs+bs])
		for j := 0; j < bs; j++ {
			plainText[i*bs+j] = prePlainText[j] ^ cipherText[(i-1)*bs+j]
		}
		//finalPlainText = append(plainText, finalPlainText...)
	}
	// for the first block
	decrypt.Decrypt(prePlainText, cipherText[:bs])
	for j := 0; j < bs; j++ {
		plainText[j] = prePlainText[j] ^ IV[j]
	}
	//finalPlainText = append(plainText, finalPlainText...)

	// check the correctness of padding
	pad := plainText[len(plainText)-1]
	n := int(pad)
	if n == 0 {
		return nil, errors.New("INVALID PADDING")
	}
	for i := len(plainText)-1; i >= len(plainText) - n; i-- {
		if plainText[i] != pad {
			return nil, errors.New("INVALID PADDING")
		}
	}
	plainText = plainText[:len(plainText) - n]

	return plainText, err

}