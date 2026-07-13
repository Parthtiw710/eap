package main

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"

	"eap/pkg"

	"github.com/joho/godotenv"
)

//go:embed public
var publicFS embed.FS

func main() {
	err := godotenv.Overload()
	if err != nil {
		log.Println("Error overloading .env file (using system environment variables instead)")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Initialize Google OAuth config
	pkg.InitOauth()

	// Initialize JWKS key configuration
	pkg.InitJWKS()

	// Initialize rate limiter
	pkg.InitLimiter()

	// Serve static files from the embedded filesystem
	http.Handle("/public/", http.FileServer(http.FS(publicFS)))

	// Parse the templates from the embedded filesystem
	tmpl, err := template.ParseFS(publicFS, "public/error.html")
	if err != nil {
		log.Fatal("Error parsing error template:", err)
	}

	// Initialize the controllers with their template/asset dependencies
	pkg.InitEapControllers(tmpl, publicFS)

	// Clean, modular routes utilizing pkg controllers
	http.HandleFunc("/error/", pkg.HandleError)
	http.HandleFunc("/auth/callback", pkg.HandleCallbackRoute)
	http.HandleFunc("/login", pkg.HandleLogin)
	http.HandleFunc("/logout", pkg.HandleLogout)
	http.HandleFunc("/.well-known/jwks.json", pkg.HandleJWKS)
	http.HandleFunc("/tunnel/poll", pkg.HandleTunnelPoll)
	http.HandleFunc("/tunnel/respond", pkg.HandleTunnelRespond)

	// Catch-all route: Handles redirects, 404s, and proxies all other requests to TARGET_URL
	http.HandleFunc("/", pkg.HandleProxy)

	// Start local tunnel in the background if enabled
	if os.Getenv("LOCAL_TUNNEL") == "true" {
		serverURL := os.Getenv("EAP_SERVER_URL")
		token := os.Getenv("TUNNEL_TOKEN")
		portStr := os.Getenv("TUNNEL_PORT")
		tunnelPort := 8081
		if portStr != "" {
			if p, err := strconv.Atoi(portStr); err == nil {
				tunnelPort = p
			}
		}
		go pkg.StartLocalTunnel(serverURL, token, tunnelPort)
	}

	log.Println("Server is running on port:", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
