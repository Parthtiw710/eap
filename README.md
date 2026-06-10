# Enterprise Authenticating Proxy (EAP) 🛡️🚀

A highly optimized, zero-trust, cloud-native authenticating reverse proxy built in Go. EAP secures target backends by providing automatic identity injection, dual-speed rate limiting, and seamless user error navigation.

Designed from the ground up to be stateless and memory-safe for **Kubernetes** and **Serverless (e.g., Google Cloud Run, AWS Fargate)** environments.

---

## Key Features 🌟

* **🔑 Multi-Cloud Identity Injection:** 
  * Automatically fetches and injects authentication headers for **GCP** (Identity Tokens), **AWS** (Cognito client credentials), **Azure** (Managed Identity tokens via IMDS), and **Kubernetes** (Service Account tokens).
  * Fallback support for **General Mode** using asymmetric RS256 JWT signatures (with JWKS public key endpoints).
* **⚡ Dual-Speed Rate Limiting (Token Bucket):** 
  * Smart identification using authenticated session emails (or IP addresses as fallback) to prevent IP-rotation bypasses.
  * **Standard User traffic:** Moderate thresholds (`3.0 req/s` refill, `5.0` burst) with graceful browser cooldown redirects.
  * **Server-to-Server (S2S) traffic:** High-throughput thresholds (`30.0 req/s` refill, `100.0` burst) utilizing Bearer tokens.
* **🛑 Premium Error & Redirection Handling:**
  * Returns direct JSON-friendly `429 Too Many Requests` status codes for automated S2S API clients.
  * Intercepts target failures and redirects web users to custom-designed, branded error pages (with automatic cooldown redirects).
* **🧠 Serverless & K8s Optimized:**
  * Fast cold starts (no external database/Redis dependencies).
  * Memory leak prevention with an automated background worker that cleans up inactive rate-limiting records.

---

## Architecture Flow 📐

```
                     ┌───────────────────────────────────┐
                     │           User Browser            │
                     └─────────────────┬─────────────────┘
                                       │ HTTPS
                                       ▼
                     ┌───────────────────────────────────┐
                     │          Cloud Edge (WAF)         │
                     └─────────────────┬─────────────────┘
                                       │ 
                                       ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        Go Proxy Server (EAP)                           │
│                                                                        │
│  1. Check Rate Limits ────► [Token Bucket (User / S2S)]                │
│  2. Authenticate User ────► [Google OAuth Validation]                  │
│  3. Inject Cloud Auth ────► [GCP / AWS / Azure / K8s Metadata token]   │
└──────────────────────────────────────┬─────────────────────────────────┘
                                       │ 
                                       ▼
                     ┌───────────────────────────────────┐
                     │          Target Backend           │
                     └───────────────────────────────────┘
```

---

## Authentication & Request Flows 🔄

EAP supports two distinct operation modes depending on how the request is made:

### 1. Browser / User Flow (Google OAuth 2.0 + Allowlist)
* **Authentication Check:** When a human visits the proxy via a browser, EAP checks for a valid session cookie (`eap_session`).
* **Google OAuth Consent:** If no valid session is found, EAP redirects the browser to the Google OAuth 2.0 login screen.
* **Email Allowlist Validation:** After a successful OAuth callback, EAP extracts the user's email address and validates it against your `ALLOWED_EMAILS` list (supports specific email addresses like `user@gmail.com` or entire domains like `@yourcompany.com`).
* **Session Management:** A secure session cookie signed with `JWT_SECRET` is set in the user's browser.
* **Rate Limiting:** Browser requests are rate-limited under standard user thresholds (`RATE_LIMIT_PER_SEC`, `RATE_BURST`) tracked by their email address (falling back to IP).

### 2. Server-to-Server (S2S) Flow (Programmatic API Clients)
* **Authentication Header:** Programmatic clients make requests by providing an `Authorization: Bearer <Token>` header.
* **OAuth Bypass:** EAP detects this header and skips the Google OAuth browser redirect flow completely.
* **Validation & Cloud Identity Injection:** The incoming request is validated, and depending on your configuration (GCP, AWS, Azure, K8s), EAP fetches and injects the corresponding cloud-native identity headers before proxying to the target service.
* **Rate Limiting:** S2S clients are rate-limited under high-throughput thresholds (`S2S_RATE_LIMIT_PER_SEC`, `S2S_RATE_BURST`) keyed by their Bearer token.

---

## Quick Start 🚀

### Pulling the Image Directly
You can pull the official pre-built Docker image directly from Docker Hub:

```bash
docker pull parth14854tiwari/eap:latest
```

### Running the Container
Run the proxy locally or on your server by passing your environment variables:

```bash
docker run -d \
  -p 8080:8080 \
  -e PORT=8080 \
  -e TARGET_URL="https://your-backend-service.com" \
  -e JWT_SECRET="your-jwt-signing-secret-key" \
  -e GOOGLE_CLIENT_ID="your-google-client-id" \
  -e GOOGLE_CLIENT_SECRET="your-google-client-secret" \
  -e GOOGLE_REDIRECT_URL="https://your-domain.com/auth/callback" \
  -e ALLOWED_EMAILS="user@gmail.com,@yourcompany.com" \
  -e RSA_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----" \
  -e GCP_ONLY=false \
  -e AWS_ONLY=false \
  -e AWS_COGNITO_TOKEN_URL="https://your-cognito-domain.auth.us-east-1.amazoncognito.com/oauth2/token" \
  -e AWS_CLIENT_ID="your-cognito-client-id" \
  -e AWS_CLIENT_SECRET="your-cognito-client-secret" \
  -e AZURE_ONLY=false \
  -e AZURE_TARGET_RESOURCE="https://database.windows.net/" \
  -e KUBERNETES_ONLY=false \
  -e RATE_LIMIT_PER_SEC=3.0 \
  -e RATE_BURST=5.0 \
  -e S2S_RATE_LIMIT_PER_SEC=30.0 \
  -e S2S_RATE_BURST=100.0 \
  parth14854tiwari/eap:latest
```

---

## Configuration Variables ⚙️

EAP is fully configured via environment variables. Copy `env.example` to `.env` to start developing.

Here is the complete template of environment variables (`env.example`):

```env
JWT_SECRET=
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URL=http://localhost:8080/auth/callback

# Comma-separated list of authorized email addresses or domain suffixes (e.g. user@gmail.com, @yourdomain.com)
ALLOWED_EMAILS=

# Target application port or url to proxy requests to (e.g. http://localhost:8000)
TARGET_URL=

# Asymmetric RSA Private Key in PEM format (for JWKS RS256 token signing)
# Generate using: openssl genrsa 2048
RSA_PRIVATE_KEY=

# Cloud Provider Mode (Set only one to true if required)
GCP_ONLY=false

AWS_ONLY=false
AWS_COGNITO_TOKEN_URL=
AWS_CLIENT_ID=
AWS_CLIENT_SECRET=

AZURE_ONLY=false
AZURE_TARGET_RESOURCE=

KUBERNETES_ONLY=false

# Rate Limiter Configurations
RATE_LIMIT_PER_SEC=3.0
RATE_BURST=5.0
S2S_RATE_LIMIT_PER_SEC=30.0
S2S_RATE_BURST=100.0
```

### Reference Table

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PORT` | The port the proxy server runs on | `8080` |
| `TARGET_URL` | The upstream destination server to proxy requests to | *(Required)* |
| `JWT_SECRET` | Secret key used for signing/verifying user session cookies | *(Required)* |
| `GOOGLE_CLIENT_ID` | OAuth2 Client ID for Google login authentication | *(Required)* |
| `GOOGLE_CLIENT_SECRET` | OAuth2 Client Secret for Google login authentication | *(Required)* |
| `GOOGLE_REDIRECT_URL` | Callback URL registered in Google Console | `http://localhost:8080/auth/callback` |
| `ALLOWED_EMAILS` | Comma-separated allowlist of emails or domain suffixes | *(Required)* |
| `RSA_PRIVATE_KEY` | Asymmetric RSA Private Key in PEM format (for JWKS token signing) | *(Optional)* |
| **Cloud Mode Selectors** | | |
| `GCP_ONLY` | Enable Google Cloud Platform identity token injection | `false` |
| `AWS_ONLY` | Enable AWS Cognito token injection | `false` |
| `AWS_COGNITO_TOKEN_URL` | Token endpoint for Cognito client credentials flow | *(Required if AWS)* |
| `AWS_CLIENT_ID` | Client ID for Cognito OAuth client | *(Required if AWS)* |
| `AWS_CLIENT_SECRET` | Client Secret for Cognito OAuth client | *(Required if AWS)* |
| `AZURE_ONLY` | Enable Azure AD Managed Identity (IMDS) injection | `false` |
| `AZURE_TARGET_RESOURCE` | The target resource ID for Azure IMDS token request | *(Required if Azure)* |
| `KUBERNETES_ONLY` | Enable Kubernetes Service Account token injection | `false` |
| **Rate Limiter Settings** | | |
| `RATE_LIMIT_PER_SEC` | Refill rate of tokens per second for standard users | `3.0` |
| `RATE_BURST` | Max burst requests allowed instantly for standard users | `5.0` |
| `S2S_RATE_LIMIT_PER_SEC` | Refill rate of tokens per second for S2S clients | `30.0` |
| `S2S_RATE_BURST` | Max burst requests allowed instantly for S2S clients | `100.0` |

---

## Local Development 🛠️

1. Clone the repository and navigate to the directory:
   ```bash
   git clone https://github.com/parth14854tiwari/eap.git
   cd eap
   ```
2. Setup environment variables:
   ```bash
   cp env.example .env
   ```
3. Run with hot reloading using `air` or standard Go run:
   ```bash
   go run main.go
   ```

---

## License 📄

This project is licensed under the **Apache License 2.0** - see the LICENSE file for details.
