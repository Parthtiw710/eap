# EAP Go Middleware

External Authentication Proxy (EAP) Middleware and Client SDK for Go.

## Installation
```bash
go get github.com/Parthtiw710/eap/libs/go
```

## Usage

```go
package main

import (
	"log"
	"net/http"

	"github.com/Parthtiw710/eap/libs/go"
)

func main() {
	// Automatically loads configuration from environment variables
	engine, err := eap.NewEngineFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello from app!"))
	})

	// Wrap handler with EAP middleware
	log.Fatal(http.ListenAndServe(":8080", engine.Middleware(mux)))
}
```

## Configuration (Environment Variables)

When initializing the engine with `eap.NewEngineFromEnv()`, EAP reads configuration directly from environment variables. Configure these variables in your host environment or `.env` file:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `JWT_SECRET` | Cryptographic secret used to sign session cookies (`HS256`). | *Required* |
| `ALLOWED_EMAILS` | Comma-separated whitelist of allowed user emails or domains (e.g. `admin@gmail.com, @iiitkota.ac.in`). | *Required* |
| `GOOGLE_CLIENT_ID` | Client ID from your Google Cloud Console Credentials. | *Required for Web OAuth* |
| `GOOGLE_CLIENT_SECRET` | Client Secret from your Google Cloud Console Credentials. | *Required for Web OAuth* |
| `GOOGLE_REDIRECT_URL` | Redirect URI registered in your Google Console (e.g., `http://localhost:8080/auth/callback`). | *Required for Web OAuth* |
| `TARGET_URL` | Set to `"tunnel"` to use localtunnel gateway, or backend service URL. | `""` |
| `TUNNEL_TOKEN` | Secure token required to authenticate tunnel clients (if `TARGET_URL=tunnel`). | `""` |
| `RATE_LIMIT_PER_SEC` | Requests per second limit for web users. | `3.0` |
| `RATE_BURST` | Max burst capacity for web users. | `5.0` |
| `S2S_RATE_LIMIT_PER_SEC` | Requests per second limit for Server-to-Server API clients. | `30.0` |
| `S2S_RATE_BURST` | Max burst capacity for Server-to-Server API clients. | `100.0` |
| `RSA_PRIVATE_KEY` | PEM encoded private key for RS256 token validation (if using cloud tokens). | `""` |
