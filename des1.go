package crtypeto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

var curve elliptic.Curve = elliptic.P256()

func main() {
	// 生成 ECDSA 私钥和公钥
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	publicKey := &privateKey.PublicKey

	// 要加密的数据
	message := []byte("hello, world!")

	// 加密数据
	ciphertext, err := encryptData(message, publicKey)
	if err != nil {
		panic(err)
	}
	se := hex.EncodeToString(ciphertext)
	// 解密数据
	plaintext, err := decryptData(se, privateKey)
	if err != nil {
		panic(err)
	}

	// 输出结果
	fmt.Println("message:", string(message))
	fmt.Println("ciphertext:", se)
	fmt.Println("plaintext:", string(plaintext))
}

// 哈希数据
func hashData(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// 加密数据
func encryptData(data []byte, publicKey *ecdsa.PublicKey) ([]byte, error) {
	// 生成临时私钥和公钥
	tempPrivateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	tempPublicKey := &tempPrivateKey.PublicKey
	fmt.Println(tempPublicKey.X)
	fmt.Println(tempPublicKey.Y)

	// 计算共享密钥
	x, y := curve.ScalarMult(publicKey.X, publicKey.Y, tempPrivateKey.D.Bytes())
	sharedKey := hashData(elliptic.Marshal(curve, x, y))

	// 加密数据
	iv := make([]byte, 16)
	rand.Read(iv)
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(data))
	stream.XORKeyStream(ciphertext, data)

	// 生成签名
	r, s, err := ecdsa.Sign(rand.Reader, tempPrivateKey, hashData(ciphertext))
	if err != nil {
		return nil, err
	}
	signature := bytes.Join([][]byte{r.Bytes(), s.Bytes()}, []byte{})

	// 合并共享密钥、加密数据和签名
	result := bytes.Join([][]byte{tempPublicKey.X.Bytes(), tempPublicKey.Y.Bytes(), iv, ciphertext, signature}, []byte{})
	return result, nil
}

// 解密数据
func decryptData(hexdata string, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	// Extract temporary public key, IV, encrypted data, and signature
	tempPublicKey := &ecdsa.PublicKey{Curve: curve}
	data, _ := hex.DecodeString(hexdata)
	tempPublicKey.X, tempPublicKey.Y = new(big.Int).SetBytes(data[:32]), new(big.Int).SetBytes(data[32:64])
	fmt.Println(tempPublicKey.X)
	fmt.Println(tempPublicKey.Y)
	iv := data[64:80]
	ciphertext := data[80 : len(data)-64]
	signature := data[len(data)-64:]

	// Calculate shared key
	x, y := curve.ScalarMult(tempPublicKey.X, tempPublicKey.Y, privateKey.D.Bytes())
	sharedKey := hashData(elliptic.Marshal(curve, x, y))

	// Verify the signature
	r := big.Int{}
	s := big.Int{}
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])
	if !ecdsa.Verify(tempPublicKey, hashData(ciphertext), &r, &s) {
		return nil, fmt.Errorf("signature verification failed")
	}

	// Decrypt the data
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}
