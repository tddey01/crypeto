package crtypeto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

func main() {
	// 待加密的数据
	plaintext := []byte("Hello, world!")

	// 选择加密算法和加密模式
	block, err := aes.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		panic(err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCTR(block, iv)

	// 加密数据
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	// 将加密后的数据转换为base64格式字符串
	encoded := hex.EncodeToString(ciphertext)
	fmt.Println("encoded:", encoded)

	// 将base64格式字符串转换为加密后的数据
	decoded, err := hex.DecodeString(encoded)
	//decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		panic(err)
	}

	// 解密数据
	decrypted := make([]byte, len(decoded))
	stream = cipher.NewCTR(block, iv)
	stream.XORKeyStream(decrypted, decoded)

	// 打印解密后的数据
	fmt.Println("decrypted:", string(decrypted))
}
