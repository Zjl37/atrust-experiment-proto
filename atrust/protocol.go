package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func dumpHex(buf []byte) {
	stdoutDumper := hex.Dumper(os.Stdout)
	defer stdoutDumper.Close()
	stdoutDumper.Write(buf)
}

func calcXRequestSig(key []byte, data []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	sum := h.Sum(nil)
	return strings.ToUpper(hex.EncodeToString(sum))
}

func randUint64() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		log.Fatalf("failed to read random bytes: %v", err)
	}
	return fmt.Sprint(binary.BigEndian.Uint64(b[:]))
}

func randHex(n int) string {
	numBytes := (n + 1) / 2
	bytes := make([]byte, numBytes)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("failed to read random bytes: %v", err)
	}
	return strings.ToUpper(hex.EncodeToString(bytes)[:n])
}

func main() {
	// server: from clientResource
	server := "183.157.160.144:441"

	conn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: 10 * time.Second,
	}, "tcp", server, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// sid: from cookie
	sid := "xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxxxx_xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxxxx"

	//////////////////////////////////////////////////////////
	// register sid, not important?

	// msg := "\x05\x01\x85"
	// message := []byte(msg)
	// n, err := conn.Write(message)
	// if err != nil {
	// 	panic(err)
	// }
	// log.Printf("send init: wrote %d bytes", n)
	// dumpHex(message[:n])

	// reply := make([]byte, 1500)
	// conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	// n, err = conn.Read(reply)
	// if err != nil {
	// 	log.Fatalf("failed to read bytes: %v", err)
	// 	panic(err)
	// }
	// log.Printf("read %d bytes", n)
	// dumpHex(reply[:n])

	// msg = fmt.Sprintf(`{"sid":"%s"}`, sid)
	// message = []byte("\x05\x01\xD0\x53\x00\x00\x53" + msg)
	// n, err = conn.Write(message)
	// if err != nil {
	// 	panic(err)
	// }
	// log.Printf("send sid: wrote %d bytes", n)
	// dumpHex(message[:n])

	// for range 1 {
	// 	reply := make([]byte, 1500)
	// 	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	// 	n, err = conn.Read(reply)
	// 	if err != nil {
	// 		log.Fatalf("failed to read bytes: %v", err)
	// 		panic(err)
	// 	}
	// 	log.Printf("read %d bytes", n)
	// 	dumpHex(reply[:n])
	// }

	// message = []byte("\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
	// n, err = conn.Write(message)
	// if err != nil {
	// 	panic(err)
	// }
	// log.Printf("send sid: wrote %d bytes", n)
	// dumpHex(message[:n])

	// for range 1 {
	// 	reply := make([]byte, 1500)
	// 	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	// 	n, err = conn.Read(reply)
	// 	if err != nil {
	// 		log.Fatalf("failed to read bytes: %v", err)
	// 		panic(err)
	// 	}
	// 	log.Printf("read %d bytes", n)
	// 	dumpHex(reply[:n])
	// }

	//////////////////////////////////////////////////////////
	// send test message

	// userName: from authCheck
	// appId: constant
	// url: tcp://ip:port
	// deviceId: constant, not important?
	// connectionId: constant-random or constant-timestamp(?), not important?
	// procHash: sha256(procPath)
	// destAddr: ip:port
	// signKey: constant, not important?

	userName := "22222222"
	appId := "xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxxxx"
	deviceId := randHex(32)
	// deviceId := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	connectionId := randHex(32) + "-" + randUint64()
	// connectionId := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" + "-" + randUint64()
	procName := "curl"
	procPath := "/usr/bin/curl"
	procHash := fmt.Sprintf("%X", sha256.Sum256([]byte(procPath)))
	signKey := randHex(64)
	// signKey := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

	log.Printf("sid: %s", sid)
	log.Printf("deviceId: %s", deviceId)
	log.Printf("connectionId: %s", connectionId)
	log.Printf("signKey: %s", signKey)

	destAddr := "10.202.41.81:80" // speedtest.zju.edu.cn
	destIP := "\x0A\xCA\x29\x51"
	destPort := "\x00\x50"
	// destAddr := "10.196.000.000:9000" // my tcp-echo-server
	// destIP := "\x0a\xc4\x00\x00"
	// destPort := "\x23\x28"

	// test
	msg := fmt.Sprintf(`{"sid":"%s","appId":"%s","url":"tcp://%s","deviceId":"%s","connectionId":"%s","procHash":"%s","userName":"%s","rcAppliedInfo":0,"lang":"en-US","destAddr":"%s","env":{"application":{"runtime":{"process":{"name":"%s","digital_signature":"TrustAppClosed","platform":"Linux","fingerprint":"%s","description":"TrustAppClosed","path":"%s","version":"TrustAppClosed","security_env":"normal"},"process_trusted":"TRUSTED"}}},"xRequestSig":""}`,
		sid, appId, destAddr, deviceId, connectionId, procHash, userName, destAddr, procName, procHash, procPath)

	// sign the message and insert the signature into it
	signKeyBytes, err := hex.DecodeString(signKey)
	if err != nil {
		panic(err)
	}
	sig := calcXRequestSig(signKeyBytes, []byte(msg))
	log.Printf("sig %s", sig)
	msg = msg[:len(msg)-3] + `"` + sig + `"}`

	// send initial message
	msgLen := len(msg)
	lenBytes := make([]byte, 2)
	lenBytes[0] = byte(msgLen >> 8)
	lenBytes[1] = byte(msgLen & 0xFF)

	message := []byte("\x05\x01\x81\x53\x03" + string(lenBytes) + msg)
	n, err := conn.Write(message)
	if err != nil {
		panic(err)
	}
	log.Printf("send initial: wrote %d bytes", n)
	dumpHex(message[:n])

	// send dest
	message = []byte("\x05\x01\x01\x01" + destIP + destPort)
	n, err = conn.Write(message)
	if err != nil {
		panic(err)
	}
	log.Printf("send dest: wrote %d bytes", n)
	dumpHex(message[:n])

	// send tcp payload data
	msg = "GET /getIP.php HTTP/1.1\r\nHost: speedtest.zju.edu.cn\r\n\r\n"
	// msg = "hi~\r\n"

	msgLen = len(msg)
	lenBytes = make([]byte, 2)
	lenBytes[0] = byte(msgLen >> 8)
	lenBytes[1] = byte(msgLen & 0xFF)

	message = []byte("\x01\x00" + string(lenBytes) + msg)
	n, err = conn.Write(message)
	if err != nil {
		panic(err)
	}
	log.Printf("send payload: wrote %d bytes", n)
	dumpHex(message[:n])

	// 05 81
	// 53 00 NN NN DD DD
	// 05 00 01 01 00 00 00 00 00 00
	// 01 00 NN NN DD DD
	for range 4 {
		reply := make([]byte, 1500)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err = conn.Read(reply)
		if err != nil {
			log.Fatalf("failed to read bytes: %v", err)
			panic(err)
		}
		log.Printf("read %d bytes", n)
		dumpHex(reply[:n])
	}

	// send close
	message = []byte("\x01\x01\x00\x00")
	n, err = conn.Write(message)
	if err != nil {
		panic(err)
	}
	log.Printf("wrote %d bytes", n)
	dumpHex(message[:n])

	for range 3 {
		reply := make([]byte, 1500)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err = conn.Read(reply)
		if err != nil {
			log.Fatalf("failed to close: %v", err)
			panic(err)
		}
		log.Printf("read %d bytes", n)
		dumpHex(reply[:n])
		if n >= 4 && string(reply[:4]) == "\x01\x01\x30\x30" {
			log.Println("done")
			break
		}
	}
}
