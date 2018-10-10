package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os/exec"
)

func main() {
	input := flag.String("i", "", "ciphertext file")
	flag.Parse()

	cipherText := readFile(*input)

	plainText := paddingOracleAttack([]byte(cipherText))
	plainText = plainText[:len(plainText)-32]
	fmt.Printf("%s",plainText)
	writeFile(plainText, "recovered_plaintext.txt")

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

func paddingOracleAttack(cipherText []byte) []byte {
	/*
	C'i-1 = Ci-1 ⊕ 00000001 ⊕ 0000000X | Ci
	 */
	IV := cipherText[:16]
	cipherText = cipherText[16:]
	oracleBlock := make([]byte, 64)
	preBlock := make([]byte, 16)
	plainText := make([]byte, 0)
	numBlock := len(cipherText) / 16

	for i := numBlock - 1; i >= 0; i-- {
		if i == 0{
			preBlock = IV
		} else {
			preBlock = cipherText[(i-1)*16:(i-1)*16+16]
		}
		for m := 0; m < 16; m++ {
			oracleBlock[48+m] = cipherText[i*16+m]
		}
		tmp := make([]byte, 16)
		try := make([]byte, 16)
		for j := 1; j <= 16; j++ {
			for n := 1; n <= j; n++ {
				tmp[16-n] = byte(j)
			}
			for k := 2; k <= 256; k++ {
				try[16 - j] = byte(k)
				for z := 0; z < 16; z++ {
					oracleBlock[32+z] = preBlock[z] ^ tmp[z] ^ try[z]
				}
				res := checkResult(oracleBlock)
				if string(res) != "INVALID PADDING" {
					break
				}
			}
		}
		//fmt.Println(try)
		plainText = append(try, plainText...)
		//fmt.Println(plainText)
	}
	pad := plainText[len(plainText)-1]
	n := int(pad)

	plainText = plainText[:len(plainText) - n]
	return plainText
}

func checkResult(oracle []byte) string {
	writeFile(oracle, "oracle.txt")
	//cmd := "./decrypt-test -i oracle.txt"
	cmd := "oracle.txt"
	out, _ := exec.Command("./decrypt-test", "-i", cmd).Output()
	return string(out)
}