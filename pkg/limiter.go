package pkg

import (
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type clientLimit struct {
	tokens   float64
	lastSeen time.Time
	isS2S    bool
}

var (
	clientsMu sync.Mutex
	clients   = make(map[string]*clientLimit)

	// Defaults for normal users: 3 requests per second, with 5 max burst
	rateLimitPerSec = 3.0
	rateBurst       = 5.0

	// Defaults for S2S (Servers): 30 requests per second, with 100 max burst
	s2sRateLimitPerSec = 30.0
	s2sRateBurst       = 100.0
)

// InitLimiter loads configurations from the environment
func InitLimiter() {
	if limitStr := os.Getenv("RATE_LIMIT_PER_SEC"); limitStr != "" {
		if val, err := strconv.ParseFloat(limitStr, 64); err == nil {
			rateLimitPerSec = val
		}
	}
	if burstStr := os.Getenv("RATE_BURST"); burstStr != "" {
		if val, err := strconv.ParseFloat(burstStr, 64); err == nil {
			rateBurst = val
		}
	}
	if s2sLimitStr := os.Getenv("S2S_RATE_LIMIT_PER_SEC"); s2sLimitStr != "" {
		if val, err := strconv.ParseFloat(s2sLimitStr, 64); err == nil {
			s2sRateLimitPerSec = val
		}
	}
	if s2sBurstStr := os.Getenv("S2S_RATE_BURST"); s2sBurstStr != "" {
		if val, err := strconv.ParseFloat(s2sBurstStr, 64); err == nil {
			s2sRateBurst = val
		}
	}

	// Start background cleanup routine
	go cleanupClients()
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// IsRateLimited checks if a client has exceeded their request limit
func IsRateLimited(r *http.Request, email string, isS2S bool) bool {
	// Track by email if logged in, otherwise fallback to IP
	key := getClientIP(r)
	if email != "" {
		key = email
	}

	clientsMu.Lock()
	defer clientsMu.Unlock()

	now := time.Now()
	client, exists := clients[key]

	// Select appropriate limits
	limitPerSec := rateLimitPerSec
	burst := rateBurst
	if isS2S {
		limitPerSec = s2sRateLimitPerSec
		burst = s2sRateBurst
	}

	if !exists {
		client = &clientLimit{
			tokens:   burst - 1.0,
			lastSeen: now,
			isS2S:    isS2S,
		}
		clients[key] = client
		log.Printf("[LIMITER] New client: %s (S2S: %v). Tokens: %.2f/%.2f", key, isS2S, client.tokens, burst)
		return false
	}

	// Add tokens since last request
	elapsed := now.Sub(client.lastSeen).Seconds()
	client.tokens += elapsed * limitPerSec
	if client.tokens > burst {
		client.tokens = burst
	}
	client.lastSeen = now

	log.Printf("[LIMITER] Client: %s (S2S: %v). Tokens before request: %.2f/%.2f", key, client.isS2S, client.tokens, burst)

	// Consume 1 token if available
	if client.tokens >= 1.0 {
		client.tokens -= 1.0
		return false
	}

	log.Printf("[LIMITER] Client RATE LIMITED: %s (S2S: %v). Tokens: %.2f", key, client.isS2S, client.tokens)
	return true
}

// cleanupClients runs periodically to remove old client records and prevent memory leaks
func cleanupClients() {
	for {
		time.Sleep(10 * time.Minute)
		clientsMu.Lock()
		now := time.Now()
		for key, client := range clients {
			if now.Sub(client.lastSeen) > 1*time.Hour {
				delete(clients, key)
			}
		}
		clientsMu.Unlock()
	}
}
