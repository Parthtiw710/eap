package pkg

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	signKey  *rsa.PrivateKey
	jwksJSON []byte
)

// InitJWKS loads the RSA private key from env and prepares the JWKS public key payload
func InitJWKS() {
	pemStr := os.Getenv("RSA_PRIVATE_KEY")
	if pemStr == "" {
		log.Println("WARNING: RSA_PRIVATE_KEY is empty. JWKS signature endpoints will fail.")
		return
	}

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		log.Println("ERROR: Failed to decode PEM block for RSA_PRIVATE_KEY")
		return
	}

	// Try PKCS#1 first, then PKCS#8 fallback
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			log.Printf("ERROR: Failed to parse RSA private key: %v", err)
			return
		}
		var ok bool
		privKey, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			log.Println("ERROR: Parsed key is not an RSA private key")
			return
		}
	}

	signKey = privKey

	// Build the corresponding JWK public key representation
	publicKey := &privKey.PublicKey
	nBytes := publicKey.N.Bytes()

	// Exponent is usually 65537 (AQAB)
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

	jwksJSON, _ = json.MarshalIndent(jwks, "", "  ")
	log.Println("JWKS endpoint initialized successfully.")
}

// HandleJWKS serves the /.well-known/jwks.json endpoint
func HandleJWKS(w http.ResponseWriter, r *http.Request) {
	if len(jwksJSON) == 0 {
		http.Error(w, "JWKS not configured or uninitialized", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jwksJSON)
}

// GenerateRS256Token signs a token with the RSA private key (used by cloud providers to verify the proxy identity)
func GenerateRS256Token(email string) (string, error) {
	if signKey == nil {
		return "", errors.New("RSA private key not configured")
	}

	claims := jwt.MapClaims{
		"iss":   "eap-proxy",
		"sub":   email,
		"email": email,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(signKey)
}

func fetchGCPIdentityToken(audience string) (string, error) {
	client := &http.Client{Timeout: 2 * time.Second}

	req, err := http.NewRequest("GET", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience="+url.QueryEscape(audience), nil)

	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavour", "Google")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("metadata server returned non 200 status")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func fetchAWSCognitoToken() (string, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	req, err := http.NewRequest("POST", os.Getenv("AWS_COGNITO_TOKEN_URL"), strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(os.Getenv("AWS_CLIENT_ID"), os.Getenv("AWS_CLIENT_SECRET"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("AWS Cognito token endpoint returned non-200 status: %d", resp.StatusCode)
	}

	var res struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}
	return res.AccessToken, nil
}

// fetchAzureIMDSToken retrieves an OAuth2 token from the Azure metadata service
func fetchAzureIMDSToken(resourceID string) (string, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest("GET", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource="+url.QueryEscape(resourceID), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Azure IMDS returned non-200 status: %d", resp.StatusCode)
	}

	var res struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}
	return res.AccessToken, nil
}

// readK8sServiceAccountToken reads the local Kubernetes projected service account token
func readK8sServiceAccountToken() (string, error) {
	tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// InjectAuthHeaders determines which cloud/asymmetric authentication is active and injects the header
func InjectAuthHeaders(req *http.Request, targetURLStr string, email string) {
	// 1. GCP Mode
	if os.Getenv("GCP_ONLY") == "true" {
		token, err := fetchGCPIdentityToken(targetURLStr)
		if err == nil && token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		} else if err != nil {
			log.Printf("GCP Identity token fetch failed: %v", err)
		}
	}

	// 2. AWS Mode
	if os.Getenv("AWS_ONLY") == "true" {
		token, err := fetchAWSCognitoToken()
		if err == nil && token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		} else if err != nil {
			log.Printf("AWS Cognito token fetch failed: %v", err)
		}
	}

	// 3. Azure Mode
	if os.Getenv("AZURE_ONLY") == "true" {
		targetResource := os.Getenv("AZURE_TARGET_RESOURCE") // Client ID of target Azure AD app
		token, err := fetchAzureIMDSToken(targetResource)
		if err == nil && token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		} else if err != nil {
			log.Printf("Azure IMDS token fetch failed: %v", err)
		}
	}

	// 4. Kubernetes Mode
	if os.Getenv("KUBERNETES_ONLY") == "true" {
		token, err := readK8sServiceAccountToken()
		if err == nil && token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		} else if err != nil {
			log.Printf("Kubernetes Service Account token read failed: %v", err)
		}
	}

	// 5. General / Default Mode (runs if no cloud-specific modes are set)
	if os.Getenv("GCP_ONLY") != "true" &&
		os.Getenv("AWS_ONLY") != "true" &&
		os.Getenv("AZURE_ONLY") != "true" &&
		os.Getenv("KUBERNETES_ONLY") != "true" {

		if email != "" && os.Getenv("RSA_PRIVATE_KEY") != "" {
			token, err := GenerateRS256Token(email)
			if err == nil && token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			} else if err != nil {
				log.Printf("Failed to generate general RS256 token: %v", err)
			}
		}
	}
}
