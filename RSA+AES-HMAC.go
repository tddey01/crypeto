package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

func padPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func unpadPKCS7(paddedData []byte) ([]byte, error) {
	length := len(paddedData)
	if length == 0 {
		return nil, fmt.Errorf("Invalid padding")
	}
	padding := int(paddedData[length-1])
	if padding > length {
		return nil, fmt.Errorf("Invalid padding")
	}
	return paddedData[:length-padding], nil
}

func encryptData(data []byte, publicKey *rsa.PublicKey, macKey []byte) ([]byte, error) {
	// 生成AES密钥
	aesKey := make([]byte, 32)
	_, err := rand.Read(aesKey)
	if err != nil {
		return nil, err
	}

	// 创建AES加密器
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	// 使用AES密钥加密数据
	paddedData := padPKCS7(data, aes.BlockSize)
	ciphertext := make([]byte, len(paddedData))
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedData)

	// 使用RSA公钥加密AES密钥
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, aesKey, nil)
	if err != nil {
		return nil, err
	}

	// 计算HMAC
	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(ciphertext)
	mac := h.Sum(nil)

	// 将加密的AES密钥、加密的数据和HMAC合并
	encryptedData := append(encryptedKey, iv...)
	encryptedData = append(encryptedData, ciphertext...)
	encryptedData = append(encryptedData, mac...)

	return encryptedData, nil
}

func decryptData(encryptedData []byte, privateKey *rsa.PrivateKey, macKey []byte) ([]byte, error) {
	// 解密AES密钥
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedData[:256], nil)
	if err != nil {
		return nil, err
	}

	// 创建AES解密器
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	// 获取IV和加密的数据
	iv := encryptedData[256 : 256+aes.BlockSize]
	ciphertext := encryptedData[256+aes.BlockSize : len(encryptedData)-sha256.Size]

	// 验证HMAC
	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(ciphertext)
	expectedMAC := h.Sum(nil)
	macStart := len(encryptedData) - sha256.Size
	if !hmac.Equal(encryptedData[macStart:], expectedMAC) {
		return nil, fmt.Errorf("MAC verification failed")
	}

	// 解密数据
	mode := cipher.NewCBCDecrypter(block, iv)
	decryptedData := make([]byte, len(ciphertext))
	mode.CryptBlocks(decryptedData, ciphertext)

	unpaddedData, err := unpadPKCS7(decryptedData)
	if err != nil {
		return nil, err
	}

	return unpaddedData, nil
}

func generateRSAKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey, nil
}

func main() {
	// 生成RSA密钥对
	privateKey, publicKey, err := generateRSAKeyPair()

	// 生成MAC密钥
	macKey := make([]byte, 32)
	_, err = rand.Read(macKey)
	if err != nil {
		fmt.Println("Failed to generate MAC key:", err)
		return
	}

	// 要加密的数据
	data := []byte("Hello,RSA+AES,encryption!")

	// 加密数据
	encryptedData, err := encryptData(data, publicKey, macKey)
	if err != nil {
		fmt.Println("Encryption error:", err)
		return
	}
	fmt.Println("Encrypted data:", encryptedData)

	// 解密数据
	decryptedData, err := decryptData(encryptedData, privateKey, macKey)
	if err != nil {
		fmt.Println("Decryption error:", err)
		return
	}
	fmt.Println("Decrypted data:", string(decryptedData))
}
