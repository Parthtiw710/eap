package pkg // Changed package name from main to pkg

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var googleOauthConfig *oauth2.Config

// InitOauth (Capitalized) initializes the config from environment variables
func InitOauth() {
	googleOauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
}

// GetLoginURL (Capitalized) generates the login URL
func GetLoginURL(state string) string {
	return googleOauthConfig.AuthCodeURL(state)
}

// HandleLogin (Capitalized) handles the redirection to Google
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	redirectTo := r.URL.Query().Get("redirect_to")
	if redirectTo == "" {
		redirectTo = "/"
	}

	url := googleOauthConfig.AuthCodeURL(redirectTo)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// HandleCallback processes the code and returns the verified email address
func HandleCallback(code string) (string, error) {
	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return "", err
	}

	client := googleOauthConfig.Client(context.Background(), token)

	res, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	var u struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(res.Body).Decode(&u); err != nil {
		return "", err
	}

	log.Printf("Parsed Google user email: %s", u.Email)
	return u.Email, nil
}
