package eap

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Config struct {
	JWTSecret            string
	RSAPrivateKey        string
	AllowedEmails        []string
	RateLimitPerSec      float64
	RateBurst            float64
	S2SRateLimitPerSec   float64
	S2SRateBurst         float64
	GoogleClientID       string
	GoogleClientSecret   string
	GoogleRedirectURL    string
	TargetURL            string
	TunnelToken          string
}

type clientLimit struct {
	tokens   float64
	lastSeen time.Time
	isS2S    bool
}

type PendingRequest struct {
	ID      string              `json:"id"`
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   string              `json:"query"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}

type TunnelResponse struct {
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}

type Engine struct {
	config                 *Config
	googleOauthConfig      *oauth2.Config
	signKey                *rsa.PrivateKey
	jwksJSON               []byte
	tokenCache             sync.Map
	clients                map[string]*clientLimit
	clientsMu              sync.Mutex
	requestCounter         uint64
	activeTunnelRequests   map[string]chan *TunnelResponse
	activeTunnelRequestsMu sync.RWMutex
	pendingTunnelRequests  chan *PendingRequest
}

func NewEngineFromEnv() (*Engine, error) {
	importOs := func(name string) string {
		return strings.TrimSpace(os.Getenv(name))
	}

	allowedEmailsStr := os.Getenv("ALLOWED_EMAILS")
	if allowedEmailsStr == "" {
		allowedEmailsStr = os.Getenv("ADMIN_EMAIL")
	}
	var allowedEmails []string
	if allowedEmailsStr != "" {
		parts := strings.Split(allowedEmailsStr, ",")
		for _, p := range parts {
			if clean := strings.TrimSpace(p); clean != "" {
				allowedEmails = append(allowedEmails, clean)
			}
		}
	}

	rateLimit, _ := strconv.ParseFloat(os.Getenv("RATE_LIMIT_PER_SEC"), 64)
	rateBurst, _ := strconv.ParseFloat(os.Getenv("RATE_BURST"), 64)
	s2sLimit, _ := strconv.ParseFloat(os.Getenv("S2S_RATE_LIMIT_PER_SEC"), 64)
	s2sBurst, _ := strconv.ParseFloat(os.Getenv("S2S_RATE_BURST"), 64)

	cfg := &Config{
		JWTSecret:          importOs("JWT_SECRET"),
		RSAPrivateKey:      os.Getenv("RSA_PRIVATE_KEY"),
		AllowedEmails:      allowedEmails,
		RateLimitPerSec:    rateLimit,
		RateBurst:          rateBurst,
		S2SRateLimitPerSec: s2sLimit,
		S2SRateBurst:       s2sBurst,
		GoogleClientID:     importOs("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: importOs("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURL:  importOs("GOOGLE_REDIRECT_URL"),
		TargetURL:          importOs("TARGET_URL"),
		TunnelToken:        importOs("TUNNEL_TOKEN"),
	}

	return NewEngine(cfg)
}

func NewEngine(cfg *Config) (*Engine, error) {
	if cfg.RateLimitPerSec <= 0 {
		cfg.RateLimitPerSec = 3.0
	}
	if cfg.RateBurst <= 0 {
		cfg.RateBurst = 5.0
	}
	if cfg.S2SRateLimitPerSec <= 0 {
		cfg.S2SRateLimitPerSec = 30.0
	}
	if cfg.S2SRateBurst <= 0 {
		cfg.S2SRateBurst = 100.0
	}

	engine := &Engine{
		config:                cfg,
		clients:               make(map[string]*clientLimit),
		activeTunnelRequests:  make(map[string]chan *TunnelResponse),
		pendingTunnelRequests: make(chan *PendingRequest, 100),
	}

	// Initialize OAuth Config
	if cfg.GoogleClientID != "" {
		engine.googleOauthConfig = &oauth2.Config{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
			RedirectURL:  cfg.GoogleRedirectURL,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.profile",
				"https://www.googleapis.com/auth/userinfo.email",
			},
			Endpoint: google.Endpoint,
		}
	}

	// Initialize JWKS & sign key
	if cfg.RSAPrivateKey != "" {
		if err := engine.initJWKS(cfg.RSAPrivateKey); err != nil {
			return nil, err
		}
	}

	// Start rate limiter cleanup
	go engine.cleanupClients()

	return engine, nil
}

func (e *Engine) initJWKS(pemStr string) error {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return errors.New("failed to decode PEM block for RSA_PRIVATE_KEY")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		var ok bool
		privKey, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return errors.New("parsed key is not an RSA private key")
		}
	}
	e.signKey = privKey

	publicKey := &privKey.PublicKey
	nBytes := publicKey.N.Bytes()
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()

	jwk := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": "eap-session-key",
		"n":   base64.RawURLEncoding.EncodeToString(nBytes),
		"e":   base64.RawURLEncoding.EncodeToString(eBytes),
	}

	jwks := map[string]interface{}{
		"keys": []interface{}{jwk},
	}

	jwksJSON, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		return err
	}
	e.jwksJSON = jwksJSON
	return nil
}

// HTTP Middleware
func (e *Engine) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bypass paths that EAP directly handles
		if r.URL.Path == "/login" || r.URL.Path == "/auth/callback" || r.URL.Path == "/logout" ||
			r.URL.Path == "/.well-known/jwks.json" || r.URL.Path == "/tunnel/poll" || r.URL.Path == "/tunnel/respond" {
			e.ServeHTTP(w, r)
			return
		}

		var email string
		var isS2S bool
		var authErr error

		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			email, authErr = e.verifySession(token)
			if authErr == nil && email != "" {
				isS2S = true
			}
		} else {
			if cookie, err := r.Cookie("eap_session"); err == nil {
				email, authErr = e.verifySession(cookie.Value)
			}
		}

		if e.isRateLimited(r, email, isS2S) {
			if isS2S {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			http.Redirect(w, r, "/error/429?redirect_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}

		if authErr != nil || email == "" {
			if isS2S {
				http.Error(w, "Unauthorized S2S token", http.StatusUnauthorized)
				return
			}
			// Redirect to login
			http.SetCookie(w, &http.Cookie{
				Name:     "redirect_to",
				Value:    r.URL.RequestURI(),
				Path:     "/",
				HttpOnly: true,
			})
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		if !e.isEmailAllowed(email) {
			http.Redirect(w, r, "/error/403", http.StatusFound)
			return
		}

		r.Header.Set("X-User-Email", email)
		next.ServeHTTP(w, r)
	})
}

func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/login":
		e.HandleLogin(w, r)
	case "/auth/callback":
		e.HandleCallbackRoute(w, r)
	case "/logout":
		e.HandleLogout(w, r)
	case "/.well-known/jwks.json":
		e.HandleJWKS(w, r)
	case "/tunnel/poll":
		e.HandleTunnelPoll(w, r)
	case "/tunnel/respond":
		e.HandleTunnelRespond(w, r)
	default:
		http.NotFound(w, r)
	}
}

// Verification Logic
func (e *Engine) verifySession(tokenString string) (string, error) {
	var claims struct {
		Email string `json:"email"`
		jwt.RegisteredClaims
	}
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(e.config.JWTSecret), nil
	})
	if err != nil || !token.Valid {
		return "", errors.New("invalid or expired session")
	}
	return claims.Email, nil
}

func (e *Engine) isEmailAllowed(email string) bool {
	emailClean := strings.ToLower(strings.TrimSpace(email))
	for _, p := range e.config.AllowedEmails {
		allowedClean := strings.ToLower(strings.TrimSpace(p))
		if allowedClean == "" {
			continue
		}
		if allowedClean == emailClean {
			return true
		}
		if strings.HasPrefix(allowedClean, "@") && strings.HasSuffix(emailClean, allowedClean) {
			return true
		}
	}
	return false
}

// Rate Limiting
func (e *Engine) isRateLimited(r *http.Request, email string, isS2S bool) bool {
	key := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		key = strings.TrimSpace(ips[0])
	}
	if email != "" {
		key = email
	}

	e.clientsMu.Lock()
	defer e.clientsMu.Unlock()

	now := time.Now()
	client, exists := e.clients[key]

	limitPerSec := e.config.RateLimitPerSec
	burst := e.config.RateBurst
	if isS2S {
		limitPerSec = e.config.S2SRateLimitPerSec
		burst = e.config.S2SRateBurst
	}

	if !exists {
		client = &clientLimit{
			tokens:   burst - 1.0,
			lastSeen: now,
			isS2S:    isS2S,
		}
		e.clients[key] = client
		return false
	}

	elapsed := now.Sub(client.lastSeen).Seconds()
	client.tokens += elapsed * limitPerSec
	if client.tokens > burst {
		client.tokens = burst
	}
	client.lastSeen = now

	if client.tokens >= 1.0 {
		client.tokens -= 1.0
		return false
	}
	return true
}

func (e *Engine) cleanupClients() {
	for {
		time.Sleep(10 * time.Minute)
		e.clientsMu.Lock()
		now := time.Now()
		for key, client := range e.clients {
			if now.Sub(client.lastSeen) > 1*time.Hour {
				delete(e.clients, key)
			}
		}
		e.clientsMu.Unlock()
	}
}

// handlers
func (e *Engine) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if e.googleOauthConfig == nil {
		http.Error(w, "OAuth not configured", http.StatusInternalServerError)
		return
	}
	redirectTo := r.URL.Query().Get("redirect_to")
	if redirectTo == "" {
		redirectTo = "/"
	}
	url := e.googleOauthConfig.AuthCodeURL(redirectTo)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (e *Engine) HandleCallbackRoute(w http.ResponseWriter, r *http.Request) {
	if e.googleOauthConfig == nil {
		http.Redirect(w, r, "/error/500", http.StatusFound)
		return
	}
	code := r.URL.Query().Get("code")
	token, err := e.googleOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Redirect(w, r, "/error/500", http.StatusFound)
		return
	}
	client := e.googleOauthConfig.Client(r.Context(), token)
	res, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Redirect(w, r, "/error/500", http.StatusFound)
		return
	}
	defer res.Body.Close()

	var u struct {
		Email string `json:"email"`
	}
	json.NewDecoder(res.Body).Decode(&u)

	if !e.isEmailAllowed(u.Email) {
		http.Redirect(w, r, "/error/403", http.StatusFound)
		return
	}

	// Generate Session JWT
	claims := jwt.MapClaims{
		"email": u.Email,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
	}
	tokenString, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(e.config.JWTSecret))

	redirectURL := "/"
	if state := r.URL.Query().Get("state"); state != "" {
		redirectURL = state
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "eap_session",
		Value:    tokenString,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400,
	})
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (e *Engine) HandleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "eap_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (e *Engine) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	if len(e.jwksJSON) == 0 {
		http.Error(w, "JWKS uninitialized", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(e.jwksJSON)
}

// Localtunnel server routes
func (e *Engine) HandleTunnelPoll(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if e.config.TunnelToken == "" || token != e.config.TunnelToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	select {
	case req := <-e.pendingTunnelRequests:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(req)
	case <-time.After(15 * time.Second):
		w.WriteHeader(http.StatusNoContent)
	case <-r.Context().Done():
	}
}

func (e *Engine) HandleTunnelRespond(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	id := r.URL.Query().Get("id")
	if e.config.TunnelToken == "" || token != e.config.TunnelToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var tunnelResp TunnelResponse
	if err := json.NewDecoder(r.Body).Decode(&tunnelResp); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	e.activeTunnelRequestsMu.RLock()
	ch, exists := e.activeTunnelRequests[id]
	e.activeTunnelRequestsMu.RUnlock()

	if exists {
		select {
		case ch <- &tunnelResp:
		default:
		}
	}
	w.WriteHeader(http.StatusOK)
}

// Proxy Request via localtunnel or direct Proxy depending on targetURL
func (e *Engine) ProxyRequest(w http.ResponseWriter, r *http.Request, email string) {
	if e.config.TargetURL == "tunnel" {
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
		}

		id := strconv.FormatUint(atomic.AddUint64(&e.requestCounter, 1), 10)
		respCh := make(chan *TunnelResponse, 1)

		e.activeTunnelRequestsMu.Lock()
		e.activeTunnelRequests[id] = respCh
		e.activeTunnelRequestsMu.Unlock()

		defer func() {
			e.activeTunnelRequestsMu.Lock()
			delete(e.activeTunnelRequests, id)
			e.activeTunnelRequestsMu.Unlock()
		}()

		headers := make(map[string][]string)
		for k, v := range r.Header {
			headers[k] = v
		}
		headers["X-User-Email"] = []string{email}

		pendingReq := &PendingRequest{
			ID:      id,
			Method:  r.Method,
			Path:    r.URL.Path,
			Query:   r.URL.RawQuery,
			Headers: headers,
			Body:    bodyBytes,
		}

		select {
		case e.pendingTunnelRequests <- pendingReq:
		default:
			http.Error(w, "Tunnel queue full", http.StatusServiceUnavailable)
			return
		}

		select {
		case resp := <-respCh:
			for k, values := range resp.Headers {
				for _, v := range values {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.Status)
			w.Write(resp.Body)
		case <-time.After(30 * time.Second):
			http.Error(w, "Tunnel Timeout", http.StatusGatewayTimeout)
		case <-r.Context().Done():
		}
		return
	}

	// Direct proxy logic
	targetURL, _ := url.Parse(e.config.TargetURL)
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		req.Host = targetURL.Host
		req.Header.Set("X-User-Email", email)
	}
	proxy.ServeHTTP(w, r)
}

// StartTunnelClient runs localtunnel client
func StartTunnelClient(serverURL, token string, localPort int) {
	localAddr := fmt.Sprintf("http://localhost:%d", localPort)
	client := &http.Client{Timeout: 45 * time.Second}
	pollURL := fmt.Sprintf("%s/tunnel/poll?token=%s", serverURL, url.QueryEscape(token))

	for {
		resp, err := client.Get(pollURL)
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		if resp.StatusCode == http.StatusNoContent {
			resp.Body.Close()
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			time.Sleep(3 * time.Second)
			continue
		}

		var req PendingRequest
		json.NewDecoder(resp.Body).Decode(&req)
		resp.Body.Close()

		go func(r PendingRequest) {
			lResp, err := forwardToLocal(r, localAddr)
			if err != nil {
				lResp = &TunnelResponse{
					Status: http.StatusBadGateway,
					Body:   []byte(err.Error()),
				}
			}
			sendResponseBack(serverURL, token, r.ID, lResp, client)
		}(req)
	}
}

func forwardToLocal(req PendingRequest, localAddr string) (*TunnelResponse, error) {
	localURL := fmt.Sprintf("%s%s", localAddr, req.Path)
	if req.Query != "" {
		localURL = fmt.Sprintf("%s?%s", localURL, req.Query)
	}
	var bodyReader io.Reader
	if req.Body != nil {
		bodyReader = bytes.NewReader(req.Body)
	}
	localReq, _ := http.NewRequest(req.Method, localURL, bodyReader)
	for k, values := range req.Headers {
		for _, v := range values {
			localReq.Header.Add(k, v)
		}
	}
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(localReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)

	headers := make(map[string][]string)
	for k, v := range resp.Header {
		headers[k] = v
	}
	return &TunnelResponse{
		Status:  resp.StatusCode,
		Headers: headers,
		Body:    bodyBytes,
	}, nil
}

func sendResponseBack(serverURL, token, id string, tResp *TunnelResponse, client *http.Client) {
	respondURL := fmt.Sprintf("%s/tunnel/respond?token=%s&id=%s", serverURL, url.QueryEscape(token), url.QueryEscape(id))
	bodyBytes, _ := json.Marshal(tResp)
	resp, err := client.Post(respondURL, "application/json", bytes.NewReader(bodyBytes))
	if err == nil {
		resp.Body.Close()
	}
}
