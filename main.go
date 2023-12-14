package main

// spark v3
// version 20231213

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

const (
	// 根据 RSA 分组
	chunkSizeEncode = 245 // 加密分块大小，根据密钥长度调整
	chunkSizeDecode = 256 // 解密分块大小
)

func main() {
	genCmd := flag.NewFlagSet("gen", flag.ExitOnError)
	genKeyName := genCmd.String("k", "key", "key name")

	signCmd := flag.NewFlagSet("sign", flag.ExitOnError)
	signFileNames := signCmd.String("f", "", "file names (separated by space)")
	signKeyName := signCmd.String("k", "key", "key name")
	signOutput := signCmd.String("o", "ok.sgn", "output file name")

	verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)
	verifyFileNames := verifyCmd.String("f", "", "file names (separated by space)")
	verifySignature := verifyCmd.String("s", "ok.sgn", "signature file name")
	verifyKeyName := verifyCmd.String("k", "key", "key name")

	encodeCmd := flag.NewFlagSet("encode", flag.ExitOnError)
	encodeFileName := encodeCmd.String("f", "", "file name")
	encodeKeyName := encodeCmd.String("k", "key", "key name")
	encodeOutputFile := encodeCmd.String("o", "encrypted", "output file name")

	decodeCmd := flag.NewFlagSet("decode", flag.ExitOnError)
	decodeFileName := decodeCmd.String("f", "", "file name")
	decodeKeyName := decodeCmd.String("k", "key", "key name")
	decodeOutputFile := decodeCmd.String("o", "decrypted", "output file name")

	if len(os.Args) < 2 {
		fmt.Println("Usage: spark.exe [command]")
		fmt.Println("Available commands: gen, sign, verify, encode, decode.")
		fmt.Println("This Project was created as a demo for XDU's 'Spark Cup', 2023.")
		fmt.Println("Using Golang, it support Windows, Linux, and other systems.")
		fmt.Println("Spark version 3 added support for encode and decode. ")
		fmt.Println("For more information, please turn to Instruction.md, or email at gaoweixu@stu.xidian.edu.cn.")
		return
	}

	switch os.Args[1] {
	case "gen":
		genCmd.Parse(os.Args[2:])
		generateKeyPair(*genKeyName)
	case "sign":
		signCmd.Parse(os.Args[2:])
		signFiles(*signFileNames, *signKeyName, *signOutput)
	case "verify":
		verifyCmd.Parse(os.Args[2:])
		verifySignatureFiles(*verifyFileNames, *verifySignature, *verifyKeyName)
	case "encode":
		encodeCmd.Parse(os.Args[2:])
		encodeFile(*encodeFileName, *encodeKeyName, *encodeOutputFile)
	case "decode":
		decodeCmd.Parse(os.Args[2:])
		decodeFile(*decodeFileName, *decodeKeyName, *decodeOutputFile)
	default:
		fmt.Println("Unknown command:", os.Args[1])
	}
}

func generateKeyPair(keyName string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Failed to generate key pair:", err)
		return
	}

	publicKey := &privateKey.PublicKey

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	err = os.WriteFile(keyName+".scrkey", privateKeyPEM, 0600)
	if err != nil {
		fmt.Println("Failed to save private key:", err)
		return
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		fmt.Println("Failed to marshal public key:", err)
		return
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	err = os.WriteFile(keyName+".pub", publicKeyPEM, 0644)
	if err != nil {
		fmt.Println("Failed to save public key:", err)
		return
	}

	fmt.Println("Key pair generated successfully.")
}

func signFiles(fileNames, keyName, outputName string) {
	privateKeyPEM, err := os.ReadFile(keyName + ".scrkey")
	if err != nil {
		fmt.Println("Failed to read private key:", err)
		return
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		fmt.Println("Invalid private key")
		return
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("Failed to parse private key:", err)
		return
	}

	files := strings.Split(fileNames, " ")
	if len(files) == 0 {
		fmt.Println("No files specified")
		return
	}

	fileData := make([]byte, 0)

	for _, fileName := range files {
		data, err := os.ReadFile(fileName)
		if err != nil {
			fmt.Println("Failed to read file:", err)
			return
		}

		fileData = append(fileData, data...)

	}

	hash := sha256.Sum256(fileData)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		fmt.Println("Failed to sign file:", err)
		return
	}

	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	err = os.WriteFile(outputName, []byte(signatureBase64), 0644)
	if err != nil {
		fmt.Println("Failed to save signature:", err)
		return
	}

	fmt.Println("Files signed successfully.")
}

func verifySignatureFiles(fileNames, signatureName, keyName string) {
	publicKeyPEM, err := os.ReadFile(keyName + ".pub")
	if err != nil {
		fmt.Println("Failed to read public key:", err)
		return
	}

	block, _ := pem.Decode(publicKeyPEM)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		fmt.Println("Invalid public key")
		return
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Println("Failed to parse public key:", err)
		return
	}
	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		fmt.Println("Invalid public key")
		return
	}

	files := strings.Split(fileNames, " ")
	if len(files) == 0 {
		fmt.Println("No files specified")
		return
	}

	fileData := make([]byte, 0)

	for _, fileName := range files {
		data, err := os.ReadFile(fileName)
		if err != nil {
			fmt.Println("Failed to read file:", err)
			return
		}

		fileData = append(fileData, data...)
	}

	hash := sha256.Sum256(fileData)
	signatureBase64, err := os.ReadFile(signatureName)
	if err != nil {
		fmt.Println("Failed to read signature:", err)
		return
	}

	signature, err := base64.StdEncoding.DecodeString(string(signatureBase64))
	if err != nil {
		fmt.Println("Failed to decode signature:", err)
		return
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		fmt.Println("Signature verification failed:", err)
		return
	}

	fmt.Println("Signature verified successfully.")
}

func encodeFile(fileName, keyName, outputFileName string) {

	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	publicKeyPEM, err := os.ReadFile(keyName + ".pub")
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(publicKeyPEM)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		log.Fatal("Failed to decode public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	rsaPublicKey := publicKey.(*rsa.PublicKey)

	outputFile, err := os.Create(outputFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer outputFile.Close()

	buffer := make([]byte, chunkSizeEncode)
	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			log.Fatal(err)
		}
		if n == 0 {
			break
		}

		encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, buffer[:n])
		if err != nil {
			log.Fatal(err)
		}

		_, err = outputFile.Write(encryptedData)
		if err != nil {
			log.Fatal(err)
		}
	}

	fmt.Printf("File %s encrypted successfully. Encrypted data saved as %s\n", fileName, outputFileName)
}

func decodeFile(fileName, keyName, outputFileName string) {
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	privateKeyPEM, err := os.ReadFile(keyName + ".scrkey")
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		log.Fatal("Failed to decode private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	outputFile, err := os.Create(outputFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer outputFile.Close()

	buffer := make([]byte, chunkSizeDecode)
	for {
		n, err := file.Read(buffer)

		if err != nil && err != io.EOF {
			log.Fatal(err)
		}

		if n == 0 {
			break
		}

		decryptedData, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, buffer[:n])
		if err != nil {
			log.Fatal(err)
		}

		_, err = outputFile.Write(decryptedData)
		if err != nil {
			log.Fatal(err)
		}

	}

	fmt.Printf("File %s decrypted successfully. Decrypted data saved as %s\n", fileName, outputFileName)
}
