package main

import (
	"crypto/aes"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
)

func main() {
	input := flag.String("i", "", "ciphertext file")
	flag.Parse()

	cipherText := readFile(*input)
	//key := "qwertyuioplkjhgfdsazxcvbnmnbvcxz"
	key :=  "qwertyuiopasdfghjklzxcvbnmnbvcxz"
	keyByte := []byte(key)
	keyEnc := keyByte[:16]
	keyMac := keyByte[16:]
	plainTextT, err:= decryptAesCBC([]byte(cipherText), keyEnc)
	if err != nil {
		fmt.Print(err)
		return
	}
	plainText := plainTextT[:len(plainTextT) - 32]
	tagT2 := plainTextT[len(plainTextT) - 32:]
	tmp := computeHmac(plainText, keyMac)
	if string(tagT2) != string(tmp) {
		fmt.Print("INVALID MAC")
		return
	}
	fmt.Println("SUCCESS")
}

func readFile(path string) string {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Print(err)
	}
	return string(content)
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
	hash.Write([]byte(k_opad))
	hash.Write([]byte(inner))
	outer := hash.Sum(nil)

	return outer

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