package crtypeto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

func main() {
	key := []byte("0123456789abcdef")  // AES-128加密密钥
	plaintext := []byte("hello world") // 待加密的数据

	// 创建AES加密算法实例
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// 对明文进行PKCS#7填充
	plaintext = pkcs7Padding(plaintext, block.BlockSize())

	// 创建CBC加密模式实例
	iv := make([]byte, aes.BlockSize)
	stream := cipher.NewCTR(block, iv)

	// 加密数据
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	// 将加密后的数据进行Base64编码
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	fmt.Println("加密后的数据：", encoded)

	// 将加密后的数据进行Base64解码
	decoded, _ := base64.StdEncoding.DecodeString(encoded)

	// 创建CBC解密模式实例
	stream = cipher.NewCTR(block, iv)

	// 解密数据
	plaintext = make([]byte, len(decoded))
	stream.XORKeyStream(plaintext, decoded)

	// 对解密后的数据进行PKCS#7去填充
	plaintext = pkcs7UnPadding(plaintext)
	fmt.Println("加密前的数据", string(plaintext))
	fmt.Println("解密后的数据：", string(plaintext))
}

// 对明文进行PKCS#7填充
func pkcs7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

// 对PKCS#7填充后的密文进行去填充
func pkcs7UnPadding(src []byte) []byte {
	length := len(src)
	unPadding := int(src[length-1])
	return src[:(length - unPadding)]
}
