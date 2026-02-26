# DNS Exfiltration Toolkit (Go) — v3.0

A complete DNS exfiltration suite in Go with per-session ephemeral key exchange, AES-GCM encryption, and rate limiting.

> ⚠️ **Educational Use Only**
> Use only on systems you own or have explicit permission to test.

---

## 🚀 Build the Binaries

```bash
go build -o dnsexfil-server ./server
go build -o dnsexfil-client ./client
```

---

## 🛡️ Encryption & Key Exchange (v3.0)

v3.0 eliminates the need for pre-shared keys. Both client and server generate **ephemeral X25519 keypairs per session**, providing true perfect forward secrecy with zero preconfiguration.

1. Client generates an ephemeral X25519 keypair and a random 8-character session ID
2. Client sends its ephemeral public key to the server via a DNS **TXT** query (Base32-encoded, multi-label subdomain)
3. Server generates its own ephemeral X25519 keypair for that session
4. Server performs ECDH, derives shared keys via **HKDF-SHA256** (32 B AES key + 16 B HMAC key), and returns its ephemeral public key in the TXT response
5. Client performs the same ECDH + HKDF derivation
6. File payload is encrypted with **AES-256-GCM** (12 B nonce ‖ ciphertext+tag), integrity-tagged with **HMAC-SHA256**, and **Base32**-encoded into DNS-safe chunks
7. Data chunks are sent as DNS **A** queries; server reassembles, verifies HMAC, decrypts, and writes the file

Key exchange is idempotent — repeated handshake requests return the cached server pubkey, allowing recovery from packet loss.

---

## 📦 Features

- **Client**:
    - Per-session ephemeral ECDH handshake via DNS TXT
    - AES-256-GCM encryption + HMAC-SHA256 integrity tag
    - Base32 encode → randomized, DNS-safe chunk sizes
    - Retries (up to 3) on failure, adjustable pacing
- **Server**:
    - DNS listener (UDP) for A & TXT queries
    - Ephemeral server keypair generated per session (no pre-shared keys)
    - Reassembles, decodes, verifies HMAC, decrypts
    - Per-IP rate limiting (configurable window and max)
    - Session TTL (10 min) with automatic cleanup every minute
    - Writes `<session-id>.bin` to `--output-dir`
---

## ⚙️ CLI Flags

### Server

| Flag                  | Default          | Description                            |
|-----------------------|------------------|----------------------------------------|
| `--port`              | `5300`           | UDP port to listen on                  |
| `--domain`            | `xf.example.com` | Delegated DNS domain                   |
| `--output-dir`        | `./output`       | Directory for recovered files          |
| `--rate-limit-window` | `60`             | Rate limit window in seconds           |
| `--rate-limit-max`    | `200`            | Max requests per IP per window         |

### Client

| Flag             | Default            | Description                                    |
|------------------|--------------------|------------------------------------------------|
| `--server-ip`    | `127.0.0.1`        | DNS server IP                                  |
| `--server-port`  | `5300`             | DNS server port                                |
| `--file-path`    | *required*         | Path to the file you want to exfiltrate        |
| `--domain`       | `xf.example.com`   | Domain suffix for DNS queries                  |
| `--low`          | `500`              | Minimum delay (ms) between queries             |
| `--high`         | `1000`             | Maximum delay (ms) between queries             |

---

## 📁 Project Structure

```
.
├── client/
│   └── client.go         # Exfiltration client
├── server/
│   └── server.go         # DNS exfiltration server
└── README.md
```

---

## 📜 License & Legal

Provided **as-is**, without warranty. Use only on systems you own or are authorized to test.
Authors accept no liability for misuse.

---

## 🧠 Credit

Original Python implementation by John Burns, now ported to Go for performance, portability, and idiomatic style.
Developed by [John Burns](https://github.com/bufo333).
