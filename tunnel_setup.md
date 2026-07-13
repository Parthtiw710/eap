# Cloud Run Function & Go HTTP Tunnel Setup Guide

This guide explains how to deploy the EAP proxy as a **Cloud Run Function (2nd Gen)** and how to run the local tunnel client from your laptop using the `pkg/localtunnel.go` module without any hardcoded credentials.

---

## 1. Cloud Run Function Deployment Code

To deploy EAP as a Cloud Run Function, create a file named `function.go` in the root of your Go project:

```go
package eap

import (
	"embed"
	"html/template"
	"net/http"
	"strings"
	"sync"

	"eap/pkg"

	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
)

//go:embed public
var publicFS embed.FS

var initOnce sync.Once

func init() {
	// Register the entry point with the Google Cloud Functions framework
	functions.HTTP("EapProxy", EapProxy)
}

// EapProxy is the Cloud Function entry point
func EapProxy(w http.ResponseWriter, r *http.Request) {
	// Strip the function name prefix from the URL path if present
	// so that routing works exactly the same as on the root '/' route.
	path := r.URL.Path
	if strings.HasPrefix(path, "/EapProxy") {
		r.URL.Path = strings.TrimPrefix(path, "/EapProxy")
	} else if strings.HasPrefix(path, "/eap-proxy") {
		r.URL.Path = strings.TrimPrefix(path, "/eap-proxy")
	}
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}

	initOnce.Do(func() {
		// Initialize Google OAuth config
		pkg.InitOauth()

		// Initialize JWKS key configuration
		pkg.InitJWKS()

		// Initialize rate limiter
		pkg.InitLimiter()

		// Parse the templates from the embedded filesystem
		tmpl, err := template.ParseFS(publicFS, "public/error.html")
		if err != nil {
			panic("Error parsing error template: " + err.Error())
		}

		// Initialize controllers
		pkg.InitEapControllers(tmpl, publicFS)

		// Register routes on the default mux
		http.HandleFunc("/error/", pkg.HandleError)
		http.HandleFunc("/auth/callback", pkg.HandleCallbackRoute)
		http.HandleFunc("/login", pkg.HandleLogin)
		http.HandleFunc("/logout", pkg.HandleLogout)
		http.HandleFunc("/.well-known/jwks.json", pkg.HandleJWKS)
		http.HandleFunc("/tunnel/poll", pkg.HandleTunnelPoll)
		http.HandleFunc("/tunnel/respond", pkg.HandleTunnelRespond)
		http.HandleFunc("/", pkg.HandleProxy)
	})

	// Serve the request using the default multiplexer
	http.DefaultServeMux.ServeHTTP(w, r)
}
```

---

## 2. Deploying the Cloud Run Function

Use the following CLI command to deploy your function to Google Cloud. 

> [!IMPORTANT]
> Make sure to pass all required EAP configuration values as environment variables. Do not hardcode these values.

```bash
gcloud functions deploy eap-proxy \
  --gen2 \
  --runtime=go122 \
  --region=asia-southeast1 \
  --entry-point=EapProxy \
  --trigger-http \
  --allow-unauthenticated \
  --set-env-vars="TARGET_URL=tunnel,TUNNEL_TOKEN=your_secure_random_token,JWT_SECRET=your_jwt_secret,CLIENT_ID=your_google_client_id,ALLOWED_EMAILS=www.parthtiwari@gmail.com,@iiitkota.ac.in"
```

## 3. Automated Running (Recommended)

You can configure the EAP server to automatically start the tunnel client in the background when it runs. This fetches and connects the tunnel automatically without needing a separate command line session.

Simply add the following to your `.env` file:
```env
LOCAL_TUNNEL=true
EAP_SERVER_URL=https://asia-southeast1-your-project.cloudfunctions.net/eap-proxy
TUNNEL_TOKEN=your_secure_random_token
TUNNEL_PORT=8081
```

Then start your EAP server normally:
```bash
go run main.go
```
The server will read these variables and automatically spin up the tunnel client in a background goroutine.
