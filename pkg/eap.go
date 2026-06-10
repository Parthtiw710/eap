package pkg

import (
	"embed"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
)

var (
	errorTmpl *template.Template
	publicFS  embed.FS
)

// InitEapControllers sets up the templates and assets for general app controllers
func InitEapControllers(tmpl *template.Template, fs embed.FS) {
	errorTmpl = tmpl
	publicFS = fs
}

// HandleError handles serving custom error pages based on HTTP status codes
func HandleError(w http.ResponseWriter, r *http.Request) {
	codeStr := r.URL.Path[len("/error/"):]
	code, err := strconv.Atoi(codeStr)
	if err != nil || code < 100 || code > 599 {
		code = http.StatusNotFound
		codeStr = "404"
	}
	imagePath := "/public/" + codeStr + ".svg"
	showText := false
	errorText := ""
	if file, err := publicFS.Open("public/" + codeStr + ".svg"); err != nil {
		imagePath = "/public/error.svg"
		showText = true
		errorText = "Error " + codeStr
	} else {
		file.Close()
	}
	w.WriteHeader(code)
	err = errorTmpl.Execute(w, map[string]interface{}{
		"Image":      imagePath,
		"ShowText":   showText,
		"ErrorText":  errorText,
		"StatusCode": code,
	})
	if err != nil {
		log.Println("Error rendering error template:", err)
	}
}

// isEmailAllowed checks if a given email is in the allowed list configured in environment variables
func isEmailAllowed(email string) bool {
	allowedStr := os.Getenv("ALLOWED_EMAILS")
	if allowedStr == "" {
		allowedStr = os.Getenv("ADMIN_EMAIL")
	}
	emailClean := strings.ToLower(strings.TrimSpace(email))

	parts := strings.Split(allowedStr, ",")
	for _, p := range parts {
		allowedClean := strings.ToLower(strings.TrimSpace(p))
		if allowedClean == "" {
			continue
		}
		if allowedClean == emailClean {
			return true
		}
		// Match domain rule (e.g. "@iiitkota.ac.in")
		if strings.HasPrefix(allowedClean, "@") && strings.HasSuffix(emailClean, allowedClean) {
			return true
		}
	}
	return false
}

func proxyRequest(w http.ResponseWriter, r *http.Request, targetURLStr string, email string) {
	targetURL, err := url.Parse(targetURLStr)
	if err != nil {
		http.Error(w, "invalid URL", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		req.Host = targetURL.Host

		// Inject platform/asymmetric auth headers dynamically managed in jwks.go
		InjectAuthHeaders(req, targetURLStr, email)

		log.Printf("→ %s %s?%s (target: %s)", req.Method, req.URL.Path, req.URL.RawQuery, targetURLStr)
	}

	// Intercept any response >= 400 from target and redirect to our styled error pages
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode >= 400 {
			origStatus := resp.StatusCode
			resp.Body.Close() // Close target backend's response body
			resp.Body = io.NopCloser(strings.NewReader(""))

			// Redirect to our styled error handler
			resp.StatusCode = http.StatusFound
			resp.Header.Set("Location", "/error/"+strconv.Itoa(origStatus))
			resp.ContentLength = 0
		}
		return nil
	}

	proxy.ServeHTTP(w, r)
}

func HandleProxy(w http.ResponseWriter, r *http.Request) {
	// Exclude auth/login/logout and assets routes so they don't get proxied if matched here
	if r.URL.Path == "/login" || r.URL.Path == "/auth/callback" || r.URL.Path == "/logout" || strings.HasPrefix(r.URL.Path, "/error/") || strings.HasPrefix(r.URL.Path, "/public/") {
		http.Redirect(w, r, "/error/404", http.StatusFound)
		return
	}

	// Rate limit check
	if IsRateLimited(r) {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		originalURL := url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, "/error/429?redirect_to="+originalURL, http.StatusFound)
		return
	}

	targetURLStr := os.Getenv("TARGET_URL")
	if targetURLStr == "" {
		http.Error(w, "Proxy target URL not configured. Set TARGET_URL in environment.", http.StatusInternalServerError)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if email, err := VerifySession(token); err == nil {
			// S2S Token valid: proxy directly
			proxyRequest(w, r, targetURLStr, email)
			return
		}

		http.Error(w, "Unauthorized S2S token", http.StatusUnauthorized)
		return
	}

	sessionCookie, err := r.Cookie("eap_session")
	if err != nil {
		// No session: save current URL and redirect to Google Login
		redirectTo := r.URL.RequestURI()
		if strings.Contains(r.URL.Path, ".") || (r.Header.Get("Accept") != "" && !strings.Contains(r.Header.Get("Accept"), "text/html")) {
			redirectTo = "/"
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "redirect_to",
			Value:    redirectTo,
			Path:     "/",
			HttpOnly: true,
		})
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	email, err := VerifySession(sessionCookie.Value)
	if err != nil {
		// Clear the invalid session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "eap_session",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})
		redirectTo := r.URL.RequestURI()
		if strings.Contains(r.URL.Path, ".") || (r.Header.Get("Accept") != "" && !strings.Contains(r.Header.Get("Accept"), "text/html")) {
			redirectTo = "/"
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "redirect_to",
			Value:    redirectTo,
			Path:     "/",
			HttpOnly: true,
		})
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if !isEmailAllowed(email) {
		// Clear unauthorized session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "eap_session",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})
		http.Redirect(w, r, "/error/403", http.StatusFound)
		return
	}

	// Proxy the request directly to target URL
	proxyRequest(w, r, targetURLStr, email)
}

func HandleCallbackRoute(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		log.Println("OAuth callback error: missing code parameter")
		http.Redirect(w, r, "/error/400", http.StatusFound)
		return
	}

	// Exchange code for user email
	email, err := HandleCallback(code)
	if err != nil {
		log.Println("OAuth callback exchange error: ", err)
		http.Redirect(w, r, "/error/500", http.StatusFound)
		return
	}

	// Check if email is allowed
	if !isEmailAllowed(email) {
		log.Printf("Unauthorized login attempt by: %s", email)
		http.Redirect(w, r, "/error/403", http.StatusFound)
		return
	}

	// Generate JWT session token
	tokenString, err := GenerateSession(email)
	if err != nil {
		log.Println("Session generation error: ", err)
		http.Redirect(w, r, "/error/500", http.StatusFound)
		return
	}

	// Retrieve redirection target
	redirectURL := "/"
	if state := r.URL.Query().Get("state"); state != "" && state != "/" {
		redirectURL = state
	} else if cookie, err := r.Cookie("redirect_to"); err == nil && cookie.Value != "" {
		redirectURL = cookie.Value
	}

	// Clear redirect cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "redirect_to",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	// Set EAP session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "eap_session",
		Value:    tokenString,
		Path:     "/",
		HttpOnly: true,  // Secure
		MaxAge:   86400, // 24 hours
	})

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func HandleLogout(w http.ResponseWriter, r *http.Request) {
	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "eap_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	// Redirect to login page
	http.Redirect(w, r, "/login", http.StatusFound)
}
