package crtypeto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/dsa"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
)

// 填充数据
func pkcs7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(ciphertext, padtext...)
}

// 反填充数据
func pkcs7Unpadding(plaintext []byte) ([]byte, error) {
	length := len(plaintext)
	unpadding := int(plaintext[length-1])
	if unpadding > length {
		return nil, errors.New("pkcs7: invalid padding")
	}

	return plaintext[:(length - unpadding)], nil
}

// 使用 AES 加密数据
func aesEncrypt(message []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 随机生成 IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// 使用 CBC 模式加密数据
	message = pkcs7Padding(message, block.BlockSize())
	ciphertext := make([]byte, aes.BlockSize+len(message))
	copy(ciphertext[:aes.BlockSize], iv)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], message)

	return ciphertext, nil
}

// 使用 AES 解密数据
func aesDecrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 获取 IV
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// 使用 CBC 模式解密数据
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	plaintext, err = pkcs7Unpadding(plaintext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// 生成 DSA 密钥
func generateDSAKey() *dsa.PrivateKey {
	privateKeyDSA := new(dsa.PrivateKey)
	privateKeyDSA.Q, _ = new(big.Int).SetString("F506C0D6C7DDAC8C2730B39E6F7719D95C4236C8E9", 32)
	privateKeyDSA.P, _ = new(big.Int).SetString("AB40E6D36E9F9F997D1E8F12852C1ABFC0DEEFDE810D81F6D110D2F26A9919B51C83D049097ED3212D02A98E382F82FBC149C038EEA1AD59AF9A1739E738F82C24732FB2175394F4B82F3C4DADC5F5F5A227E7722709A2D7E81A905B3697EEB4B4C3D4B8F246D0837A824C4919B7657D8F290BE2DDA81E1A1A237E84DF", 32)
	privateKeyDSA.G, _ = new(big.Int).SetString("69C9401D22C66EF837AD7D8C437EDB2B2E9B49C11D9656DB1F131DD553CA6E35781C2D2FE8B3D97F17D2089F3DBB3A8C35AE1D1CDEA0E9366E25D6C52A0852A0E121888907F89CC7106C7A6F346A25715D55C2B16645D87617C2319CC6A352D3C92D4C7CB72841FF4B4D4DB3F1B9255D5F9B01E12D41C522012B8CE37D2", 32)
	err := dsa.GenerateParameters(&privateKeyDSA.Parameters, rand.Reader, dsa.L2048N256)
	if err != nil {
		log.Fatal(err)
	}
	err = dsa.GenerateKey(privateKeyDSA, rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return privateKeyDSA
}

func dsaSign(message []byte, privateKey *dsa.PrivateKey) ([]byte, error) {
	// 计算哈希值
	//hash := sha256.Sum256(message)
	hash := sha512.Sum512(message)

	// 生成随机数 k
	k, err := rand.Int(rand.Reader, privateKey.Q)
	if err != nil {
		return nil, err
	}

	// 计算 r = (g^k mod p) mod q
	r := new(big.Int).Exp(privateKey.G, k, privateKey.P)
	r.Mod(r, privateKey.Q)

	// 计算 s = (k^-1 (hash + x * r)) mod q
	kInv := new(big.Int).ModInverse(k, privateKey.Q)
	s1 := new(big.Int).Mul(privateKey.X, r)
	s2 := new(big.Int).Add(new(big.Int).SetBytes(hash[:]), s1)
	s := new(big.Int).Mul(kInv, s2)
	s.Mod(s, privateKey.Q)

	// 将 r 和 s 合并为签名
	signature := make([]byte, 2*privateKey.Q.BitLen()/8)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(signature[len(signature)/2-len(rBytes):], rBytes)
	copy(signature[len(signature)-len(sBytes):], sBytes)

	return signature, nil
}

func dsaVerify(message []byte, signature []byte, publicKey *dsa.PublicKey) error {

	// 从字节流中解析出 r 和 s
	r := new(big.Int)
	s := new(big.Int)
	r.SetBytes(signature[:len(signature)/2])
	s.SetBytes(signature[len(signature)/2:])

	// 计算哈希值
	//hash := sha256.Sum256(message)
	hash := sha512.Sum512(message)
	// 计算 w = s^-1 mod q
	w := new(big.Int).ModInverse(s, publicKey.Q)

	// 计算 u1 = (hash * w) mod q 和 u2 = (r * w) mod q
	u1 := new(big.Int).Mul(new(big.Int).SetBytes(hash[:]), w)
	u1.Mod(u1, publicKey.Q)
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, publicKey.Q)

	// 计算 v = ((g^u1 * y^u2) mod p) mod q
	v1 := new(big.Int).Exp(publicKey.G, u1, publicKey.P)
	v2 := new(big.Int).Exp(publicKey.Y, u2, publicKey.P)
	v := new(big.Int).Mul(v1, v2)
	v.Mod(v, publicKey.P)
	v.Mod(v, publicKey.Q)

	// 如果 v 等于 r，则验证通过
	if v.Cmp(r) == 0 {
		return nil
	}

	return errors.New("dsa: invalid signature")
}

func main() {
	// 生成 DSA 密钥
	privateKeyDSA := generateDSAKey()
	// 加密数据
	key := []byte("0123456789abcdef")
	message := []byte("Hello, world!")
	ciphertext, err := aesEncrypt(message, key)
	if err != nil {
		log.Fatal(err)
	}

	// 签名加密后的数据
	signature, err := dsaSign(ciphertext, privateKeyDSA)
	if err != nil {
		log.Fatal(err)
	}

	// 验证签名并解密数据
	err = dsaVerify(ciphertext, signature, &privateKeyDSA.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	plaintext, err := aesDecrypt(ciphertext, key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(message))
	fmt.Println(hex.EncodeToString(ciphertext))
	fmt.Println(hex.EncodeToString(signature))
	fmt.Println(string(plaintext))
}
