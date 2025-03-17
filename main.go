package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const bufferSize = 4096

// Generate a self-signed TLS certificate
func generateTLSCert(certFile, keyFile string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	tmpl := x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{Organization: []string{"ShadowX Secure File Transfer"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certFileHandle, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certFileHandle.Close()
	pem.Encode(certFileHandle, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyFileHandle, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer keyFileHandle.Close()
	pem.Encode(keyFileHandle, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return nil
}

// Start the server
func startServer(address, secretKey string) {
	// Generate TLS certificate if it doesn't exist
	if _, err := os.Stat("server.crt"); os.IsNotExist(err) {
		if err := generateTLSCert("server.crt", "server.key"); err != nil {
			fmt.Println("Error generating TLS certificate:", err)
			return
		}
	}

	// Load the certificate
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		fmt.Println("Error loading certificate:", err)
		return
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Start the TLS listener
	listener, err := tls.Listen("tcp", address, tlsConfig)
	if err != nil {
		fmt.Println("Error starting server:", err)
		return
	}
	defer listener.Close()
	fmt.Println("ShadowX Server listening on", address)

	// Accept incoming connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		go handleConnection(conn, secretKey)
	}
}

// Handle client connections
func handleConnection(conn net.Conn, secretKey string) {
	defer conn.Close()
	fmt.Println("Client connected:", conn.RemoteAddr())

	buf := make([]byte, bufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Error reading authentication key:", err)
		return
	}
	authKey := strings.TrimSpace(string(buf[:n]))

	if authKey != secretKey {
		fmt.Println("Invalid authentication key! Disconnecting client:", conn.RemoteAddr())
		conn.Write([]byte("Authentication failed\n"))
		return
	}
	conn.Write([]byte("Authentication successful\n"))
	fmt.Println("Client authenticated successfully")

	n, err = conn.Read(buf)
	if err != nil {
		fmt.Println("Error reading file metadata:", err)
		return
	}
	metadata := strings.TrimSpace(string(buf[:n]))
	parts := strings.SplitN(metadata, " ", 2)
	if len(parts) != 2 || parts[0] != "upload" {
		fmt.Println("Invalid transfer request")
		return
	}
	filename := parts[1]
	fmt.Println("Receiving:", filename)

	receiveFile(conn, filename)
}

// Receive a file from the client
func receiveFile(conn net.Conn, filename string) {
	if err := os.MkdirAll(filepath.Dir(filename), os.ModePerm); err != nil {
		fmt.Println("Error creating directories:", err)
		return
	}

	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	buffer := make([]byte, bufferSize)
	var received int64
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			_, writeErr := file.Write(buffer[:n])
			if writeErr != nil {
				fmt.Println("Error writing to file:", writeErr)
				return
			}
			received += int64(n)
			fmt.Printf("\rReceived: %d bytes", received)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("Error receiving file:", err)
			return
		}
	}
	fmt.Printf("\nFile received successfully: %s\n", filename)
}

// Send files to the server
func sendFile(serverAddress, path, secretKey string) {
	// Check if the path is a directory or a single file
	fileInfo, err := os.Stat(path)
	if err != nil {
		fmt.Println("Error accessing file or directory:", err)
		return
	}

	if fileInfo.IsDir() {
		// If it's a directory, walk through all files
		filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
			if err != nil {
				fmt.Println("Error accessing file:", err)
				return nil
			}
			if !info.IsDir() {
				fmt.Println("Sending:", filePath)
				sendSingleFile(serverAddress, filePath, secretKey)
			}
			return nil
		})
	} else {
		// If it's a single file, send it directly
		fmt.Println("Sending:", path)
		sendSingleFile(serverAddress, path, secretKey)
	}
}

// Send a single file to the server
func sendSingleFile(serverAddress, filename, secretKey string) {
	// Validate file existence
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		fmt.Println("File does not exist:", filename)
		return
	}

	// Connect to the server
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", serverAddress, tlsConfig)
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer conn.Close()

	// Send authentication key
	_, err = conn.Write([]byte(secretKey + "\n"))
	if err != nil {
		fmt.Println("Error sending authentication key:", err)
		return
	}

	// Read server response
	buf := make([]byte, bufferSize)
	n, err := conn.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "Authentication successful") {
		fmt.Println("Authentication failed. Server response:", string(buf[:n]))
		return
	}

	// Send file metadata
	_, err = fmt.Fprintf(conn, "upload %s\n", filename)
	if err != nil {
		fmt.Println("Error sending file metadata:", err)
		return
	}

	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// Send file content
	fileInfo, _ := file.Stat()
	totalSize := fileInfo.Size()
	buffer := make([]byte, bufferSize)
	var sent int64

	for {
		n, err := file.Read(buffer)
		if n > 0 {
			_, writeErr := conn.Write(buffer[:n])
			if writeErr != nil {
				fmt.Println("Error sending file data:", writeErr)
				return
			}
			sent += int64(n)
			fmt.Printf("\rSent: %d/%d bytes (%.2f%%)", sent, totalSize, (float64(sent)/float64(totalSize))*100)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}
	}
	fmt.Printf("\nFile sent successfully: %s\n", filename)
}

// Main function
func main() {
	ip := flag.String("i", "127.0.0.1:8080", "IP and port to bind/listen")
	password := flag.String("p", "", "Pre-Shared Key (PSK) for authentication")
	filePath := flag.String("f", "", "File or directory to send")

	flag.Usage = func() {
		fmt.Println("ShadowX - Secure File Transfer")
		fmt.Println("\nUsage:")
		fmt.Println("  Server Mode (default):")
		fmt.Println("    ./ShadowX -i 0.0.0.0:8080 -p mysecretkey")
		fmt.Println("\n  Client Mode (send file):")
		fmt.Println("    ./ShadowX -i 192.168.1.100:8080 -p mysecretkey -f myfile.txt")
	}

	flag.Parse()

	if *password == "" {
		flag.Usage()
		return
	}

	if *filePath != "" {
		// Client mode: Send file(s)
		sendFile(*ip, *filePath, *password)
	} else {
		// Server mode: Start server
		startServer(*ip, *password)
	}
}