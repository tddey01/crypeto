package crtypeto

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

func main() {
	// 生成RSA密钥对
	privateKeyRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// 生成DSA密钥对
	parametersDSA := &dsa.Parameters{}
	if err := dsa.GenerateParameters(parametersDSA, rand.Reader, dsa.L2048N256); err != nil {
		panic(err)
	}
	privateKeyDSA := new(dsa.PrivateKey)
	privateKeyDSA.PublicKey.Parameters = *parametersDSA
	if err := dsa.GenerateKey(privateKeyDSA, rand.Reader); err != nil {
		panic(err)
	}

	// 待加密的数据
	message := []byte("Hello, world!")

	// 使用公钥加密数据
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privateKeyRSA.PublicKey, message, nil)
	if err != nil {
		panic(err)
	}

	// 使用私钥解密数据
	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKeyRSA, encrypted, nil)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	fmt.Printf("原始数据：%s\n", message)
	fmt.Printf("加密后的数据：%x\n", encrypted)
	fmt.Printf("解密后的数据：%s\n", decrypted)

	// 对数据进行哈希
	hashed := sha256.Sum256(message)

	// 使用DSA签名数据
	r, s, err := dsa.Sign(rand.Reader, privateKeyDSA, hashed[:])
	if err != nil {
		panic(err)
	}

	// 使用DSA验证签名
	if !dsa.Verify(&privateKeyDSA.PublicKey, hashed[:], r, s) {
		panic("签名验证失败")
	}

	fmt.Println("签名验证成功")
}
