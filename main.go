package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	authRequired := os.Getenv("PROXY_USER") != ""

	method, ok := negotiateAuth(conn, authRequired)
	if !ok {
		return
	}

	if method == 0x02 {
		if !authenticate(conn) {
			return
		}
	}

	targetConn, rep, err := handleConnect(conn)
	if err != nil {
		sendReply(conn, rep)
		return
	}
	defer targetConn.Close()

	sendReply(conn, 0x00)
	relay(conn, targetConn)
}

func negotiateAuth(conn net.Conn, authRequired bool) (byte, bool) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, false
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, false
	}

	requiredMethod := byte(0x00)
	if authRequired {
		requiredMethod = 0x02
	}

	for _, method := range methods {
		if method == requiredMethod {
			conn.Write([]byte{0x05, requiredMethod})
			return requiredMethod, true
		}
	}

	conn.Write([]byte{0x05, 0xFF})
	return 0, false
}

func authenticate(conn net.Conn) bool {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return false
	}

	usernameLength := int(header[1])
	username := make([]byte, usernameLength)
	if _, err := io.ReadFull(conn, username); err != nil {
		return false
	}

	passwordLengthByte := make([]byte, 1)
	if _, err := io.ReadFull(conn, passwordLengthByte); err != nil {
		return false
	}

	passwordLength := int(passwordLengthByte[0])
	password := make([]byte, passwordLength)
	if _, err := io.ReadFull(conn, password); err != nil {
		return false
	}

	if string(username) == os.Getenv("PROXY_USER") &&
		string(password) == os.Getenv("PROXY_PASS") {
		conn.Write([]byte{0x01, 0x00})
		return true
	}

	conn.Write([]byte{0x01, 0x01})
	return false
}

func handleConnect(conn net.Conn) (net.Conn, byte, error) {
	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil {
		return nil, 0x01, err
	}

	if request[0] != 0x05 {
		return nil, 0x01, fmt.Errorf("invalid SOCKS version")
	}

	if request[1] != 0x01 {
		return nil, 0x07, fmt.Errorf("only CONNECT is supported")
	}

	addressType := request[3]
	var host string

	switch addressType {
	case 0x01:
		ipBytes := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBytes); err != nil {
			return nil, 0x01, err
		}
		host = net.IP(ipBytes).String()

	case 0x03:
		lengthByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lengthByte); err != nil {
			return nil, 0x01, err
		}

		domainBytes := make([]byte, int(lengthByte[0]))
		if _, err := io.ReadFull(conn, domainBytes); err != nil {
			return nil, 0x01, err
		}
		host = string(domainBytes)

	default:
		return nil, 0x08, fmt.Errorf("unsupported address type")
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return nil, 0x01, err
	}

	port := binary.BigEndian.Uint16(portBytes)
	targetAddress := host + ":" + strconv.Itoa(int(port))

	targetConn, err := net.Dial("tcp", targetAddress)
	if err != nil {
		return nil, 0x05, err
	}

	return targetConn, 0x00, nil
}

func sendReply(conn net.Conn, replyCode byte) {
	reply := []byte{
		0x05,
		replyCode,
		0x00,
		0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}

	conn.Write(reply)
}

func relay(client net.Conn, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(target, client)

		if tcpTarget, ok := target.(*net.TCPConn); ok {
			tcpTarget.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, target)

		if tcpClient, ok := client.(*net.TCPConn); ok {
			tcpClient.CloseWrite()
		}
	}()

	wg.Wait()
}
