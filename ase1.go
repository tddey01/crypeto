package crtypeto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

func main() {
	key := []byte("0123456789abcdef0123456789abcdef") // 32字节的AES-256密钥
	plaintext := []byte("Hello, world!")              // 要加密的数据

	// 加密数据
	ciphertext, err := encrypt(key, plaintext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("加密后的数据：%s\n", base64.StdEncoding.EncodeToString(ciphertext))

	// 解密数据
	decryptedText, err := decrypt(key, ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("解密后的数据：%s\n", decryptedText)
}

// 加密数据
func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 创建一个随机的IV向量
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// 使用AES-CBC模式加密数据
	mode := cipher.NewCBCEncrypter(block, iv)
	padded := pkcs7Padding(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)

	// 将IV向量和密文拼接起来
	result := make([]byte, len(iv)+len(ciphertext))
	copy(result, iv)
	copy(result[len(iv):], ciphertext)

	return result, nil
}

// 解密数据
func decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 检查密文长度是否正确
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("密文太短")
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("密文长度不是块大小的倍数")
	}

	// 从密文中提取IV向量
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// 使用AES-CBC模式解密数据
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// 去除填充字节
	unpadded, err := pkcs7Unpadding(plaintext, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return unpadded, nil
}

// 对数据进行PKCS7填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// 对数据进行PKCS7反向填充

func pkcs7Unpadding(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("数据为空")
	}
	unpadding := int(data[length-1])
	if length < unpadding {
		return nil, errors.New("填充字节错误")
	}
	return data[:(length - unpadding)], nil
}
