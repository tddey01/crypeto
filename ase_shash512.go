package crtypeto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"log"
)

// 对数据进行填充
func pkcs7Pad(data []byte, blockSize int) []byte {
	padSize := blockSize - len(data)%blockSize
	pad := bytes.Repeat([]byte{byte(padSize)}, padSize)
	return append(data, pad...)
}

// 对填充后的数据进行去除填充
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("pkcs7: invalid padding (empty input)")
	}
	padSize := int(data[len(data)-1])
	if padSize > len(data) {
		return nil, fmt.Errorf("pkcs7: invalid padding (pad size %d is larger than data)", padSize)
	}
	pad := data[len(data)-padSize:]
	for _, b := range pad {
		if b != byte(padSize) {
			return nil, errors.New("pkcs7: invalid padding (bad padding)")
		}
	}
	return data[:len(data)-padSize], nil
}

// 对数据进行AES加密
func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	// 创建一个新的AES块密码，将密钥填充到块长度
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// 对明文数据进行填充
	paddedData := pkcs7Pad(plaintext, aes.BlockSize)

	// 创建一个新的加密器，并对填充后的数据进行加密
	ciphertext := make([]byte, aes.BlockSize+len(paddedData))
	iv := ciphertext[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)

	if err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)

	cfb.XORKeyStream(ciphertext[aes.BlockSize:], paddedData)

	// 返回加密后的密文
	return ciphertext, nil
}

// 对数据进行AES解密
func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	// 创建一个新的AES块密码，将密钥填充到块长度
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 检查密文长度是否至少为块长度
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	// 解密前16个字节以获取IV
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// 创建一个新的解密器，并对密文进行解密
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(ciphertext, ciphertext)

	// 对解密后的数据进行去除填充
	plaintext, err := pkcs7Unpad(ciphertext)
	if err != nil {
		return nil, err
	}

	// 返回解密后的明文
	return plaintext, nil
}

// 对密钥进行哈希
func hashKey(key []byte) []byte {
	h := sha512.New()
	h.Write(key)
	hashed := h.Sum(nil)
	return hashed[:32]
}

func main() {
	plaintext := []byte("Hello, World!") // 待加密的明文
	key := []byte("my-secret-key")       // 密钥
	fmt.Printf("加密前的数据: %s\n", plaintext)
	// 对密钥进行哈希处理
	hashedKey := hashKey(key)
	// 对明文进行加密
	ciphertext, err := encrypt(plaintext, hashedKey)

	if err != nil {
		log.Fatal(err)
	}

	// 对密文进行解密
	decrypted, err := decrypt(ciphertext, hashedKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("加密后的数据: %x\n", ciphertext)
	fmt.Printf("解密后的数据: %s\n", decrypted)
}
