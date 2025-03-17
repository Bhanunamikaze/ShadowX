# ShadowX - Secure File Transfer

ShadowX is a secure file transfer application that allows you to transfer files between a client and a server using **Pre-Shared Key (PSK) authentication** and **TLS encryption**. It ensures secure and reliable file transfers over a network.

---

## Features

- **Secure File Transfer**: Uses TLS encryption to protect data in transit.
- **Pre-Shared Key (PSK) Authentication**: Ensures only authorized clients can connect to the server.
- **Directory Support**: Can send entire directories recursively.
- **Self-Signed Certificates**: Automatically generates self-signed certificates for TLS encryption.
- **Cross-Platform**: Works on any platform that supports Go.

---

## Installation

### Prerequisites

- [Go](https://golang.org/dl/) installed on your system.

### Build from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/bhanunamikaze/ShadowX.git
   cd ShadowX
   ```

2. Build the application:
   ```bash
   go build -ldflags "-s -w" -o ShadowX
   ```

3. Run the application:
   - For server mode:
     ```bash
     ./ShadowX -i 0.0.0.0:8080 -p mysecretkey
     ```
   - For client mode:
     ```bash
     ./ShadowX -i 192.168.1.5:8080 -p mysecretkey -f myfile.txt
     ```

---

## Usage

### Server Mode

Start the server by specifying the IP address, port, and pre-shared key (PSK):

```bash
./ShadowX -i 0.0.0.0:8080 -p mysecretkey
```

- The server will listen for incoming connections on the specified IP and port.
- It will automatically generate a self-signed certificate if one does not exist.

### Client Mode

Send files or directories to the server by specifying the server's IP address, port, PSK, and file/directory path:

```bash
./ShadowX -i 127.0.0.1:8080 -p mysecretkey -f myfile.txt
```

- To send a directory:
  ```bash
  ./ShadowX -i 127.0.0.1:8080 -p mysecretkey -f mydir/
  ```

---

## Command-Line Arguments

| Argument | Description                                      | Example                          |
|----------|--------------------------------------------------|----------------------------------|
| `-i`     | IP address and port to bind/listen               | `-i 0.0.0.0:8080`               |
| `-p`     | Pre-Shared Key (PSK) for authentication          | `-p mysecretkey`                |
| `-f`     | File or directory to send (client mode only)     | `-f myfile.txt` or `-f mydir/`  |

---

## Example Workflow

1. **Start the Server**:
   ```bash
   ./ShadowX -i 0.0.0.0:8080 -p mysecretkey
   ```

2. **Send a File from the Client**:
   ```bash
   ./ShadowX -i 127.0.0.1:8080 -p mysecretkey -f myfile.txt
   ```

3. **Send a Directory from the Client**:
   ```bash
   ./ShadowX -i 127.0.0.1:8080 -p mysecretkey -f mydir/
   ```

---
## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
