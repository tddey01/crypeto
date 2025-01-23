package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/dh"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"golang.org/x/crypto/pbkdf2"
)

// 生成 Diffie-Hellman 参数
func generateDHParameters() (*dh.Parameters, error) {
	params, err := dh.GenerateParameters(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return params, nil
}

// 生成 Diffie-Hellman 密钥对（私钥和公钥）
func generateKeyPair(params *dh.Parameters) (*dh.PrivateKey, *dh.PublicKey, error) {
	privKey, pubKey, err := dh.GenerateKey(rand.Reader, params)
	if err != nil {
		return nil, nil, err
	}
	return privKey, pubKey, nil
}

// 计算共享密钥
func computeSharedSecret(privKey *dh.PrivateKey, otherPubKey *dh.PublicKey) ([]byte, error) {
	sharedSecret, err := privKey.ComputeSecret(otherPubKey)
	if err != nil {
		return nil, err
	}
	return sharedSecret, nil
}

// 使用 AES 加密数据
func encryptAES(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

// 使用 AES 解密数据
func decryptAES(encryptedData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func handleConnection(conn net.Conn, params *dh.Parameters) {
	defer conn.Close()

	// 生成服务端的密钥对
	privServer, pubServer, err := generateKeyPair(params)
	if err != nil {
		log.Fatal("生成服务端密钥对失败:", err)
	}

	// 发送公钥给客户端
	pubServerBytes, err := pubServer.Marshal()
	if err != nil {
		log.Fatal("序列化服务端公钥失败:", err)
	}
	_, err = conn.Write(pubServerBytes)
	if err != nil {
		log.Fatal("发送公钥失败:", err)
	}

	// 接收客户端的公钥
	clientPubKey := make([]byte, 256)
	_, err = conn.Read(clientPubKey)
	if err != nil {
		log.Fatal("读取客户端公钥失败:", err)
	}
	clientPubKeyObj := &dh.PublicKey{}
	clientPubKeyObj.Unmarshal(clientPubKey)

	// 计算共享密钥
	sharedSecret, err := computeSharedSecret(privServer, clientPubKeyObj)
	if err != nil {
		log.Fatal("计算共享密钥失败:", err)
	}

	// 使用 PBKDF2 派生 AES 密钥
	aesKey := pbkdf2.Key(sharedSecret, []byte("salt"), 1000, 32, nil)

	// 接收加密数据
	encryptedData := make([]byte, 1024)
	n, err := conn.Read(encryptedData)
	if err != nil {
		log.Fatal("读取加密数据失败:", err)
	}

	// 解密数据
	decryptedData, err := decryptAES(encryptedData[:n], aesKey)
	if err != nil {
		log.Fatal("解密数据失败:", err)
	}

	// 打印解密后的数据
	fmt.Printf("接收到的数据: %s\n", string(decryptedData))

	// 回复客户端，加密返回数据
	response := "Hello from server"
	encryptedResponse, err := encryptAES([]byte(response), aesKey)
	if err != nil {
		log.Fatal("加密返回数据失败:", err)
	}
	_, err = conn.Write(encryptedResponse)
	if err != nil {
		log.Fatal("发送加密数据失败:", err)
	}
}

func main() {
	params, err := generateDHParameters()
	if err != nil {
		log.Fatal("生成 DH 参数失败:", err)
	}

	listen, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal("服务端监听失败:", err)
	}
	defer listen.Close()

	fmt.Println("服务端已启动，等待客户端连接...")

	// 等待客户端连接并处理请求
	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Fatal("接收客户端连接失败:", err)
		}
		go handleConnection(conn, params)
	}
}


package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/dh"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"golang.org/x/crypto/pbkdf2"
)

// 生成 Diffie-Hellman 参数
func generateDHParameters() (*dh.Parameters, error) {
	params, err := dh.GenerateParameters(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return params, nil
}

// 生成 Diffie-Hellman 密钥对（私钥和公钥）
func generateKeyPair(params *dh.Parameters) (*dh.PrivateKey, *dh.PublicKey, error) {
	privKey, pubKey, err := dh.GenerateKey(rand.Reader, params)
	if err != nil {
		return nil, nil, err
	}
	return privKey, pubKey, nil
}

// 计算共享密钥
func computeSharedSecret(privKey *dh.PrivateKey, otherPubKey *dh.PublicKey) ([]byte, error) {
	sharedSecret, err := privKey.ComputeSecret(otherPubKey)
	if err != nil {
		return nil, err
	}
	return sharedSecret, nil
}

// 使用 AES 加密数据
func encryptAES(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

// 使用 AES 解密数据
func decryptAES(encryptedData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func main() {
	// 生成 Diffie-Hellman 参数
	params, err := generateDHParameters()
	if err != nil {
		log.Fatal("生成 DH 参数失败:", err)
	}

	// 客户端生成自己的密钥对
	privClient, pubClient, err := generateKeyPair(params)
	if err != nil {
		log.Fatal("生成客户端密钥对失败:", err)
	}

	// 连接到服务端
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		log.Fatal("连接服务端失败:", err)
	}
	defer conn.Close()

	// 发送客户端的公钥
	pubClientBytes, err := pubClient.Marshal()
	if err != nil {
		log.Fatal("序列化客户端公钥失败:", err)
	}
	_, err = conn.Write(pubClientBytes)
	if err != nil {
		log.Fatal("发送公钥失败:", err)
	}

	// 接收服务端的公钥
	serverPubKey := make([]byte, 256)
	_, err = conn.Read(serverPubKey)
	if err != nil {
		log.Fatal("读取服务端公钥失败:", err)
	}
	serverPubKeyObj := &dh.PublicKey{}
	serverPubKeyObj.Unmarshal(serverPubKey)

	// 计算共享密钥
	sharedSecret, err := computeSharedSecret(privClient, serverPubKeyObj)
	if err != nil {
		log.Fatal("计算共享密钥失败:", err)
	}

	// 使用 PBKDF2 派生 AES 密钥
	aesKey := pbkdf2.Key(sharedSecret, []byte("salt"), 1000, 32, nil)

	// 客户端发送加密数据
	message := "Hello from client"
	encryptedMessage, err := encryptAES([]byte(message), aesKey)
	if err != nil {
		log.Fatal("加密消息失败:", err)
	}
	_, err = conn.Write(encryptedMessage)
	if err != nil {
		log.Fatal("发送加密数据失败:", err)
	}

	// 接收服务端返回的加密响应
	encryptedResponse := make([]byte, 1024)
	n, err := conn.Read(encryptedResponse)
	if err != nil {
		log.Fatal("读取加密响应失败:", err)
	}

	// 解密服务端的响应
	decryptedResponse, err := decryptAES(encryptedResponse[:n], aesKey)
	if err != nil {
		log.Fatal("解密服务端响应失败:", err)
	}

	// 打印解密后的响应
	fmt.Printf("接收到的服务端消息: %s\n", string(decryptedResponse))
}
