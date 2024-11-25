package main

import (
	"fmt"
	"log"
	"net/http" //for HTTP server
	"os"
	"f5.com/ha/api_sec"
	"github.com/joho/godotenv"
)

func loadEnv() {
	//Load the .env file
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
		log.Fatal(err)
	}
}

// A different middleware is required for different balance and account requests.
// get doesn't need content type json verifier since there's no body in this request.
// post and delete need both content type json and auth.
func MethodRouter(w http.ResponseWriter, r *http.Request, handler func(http.ResponseWriter, *http.Request, *api_sec.Claims)) {
	log.Println("Reached Method Router")
	switch r.Method {
	case http.MethodDelete, http.MethodPost:
		// Apply ContentTypeJSON and Auth middleware
		api_sec.ContentTypeJSON(api_sec.Auth(func(w http.ResponseWriter, r *http.Request, claims *api_sec.Claims) {
			handler(w, r, claims) // Pass claims to the handler
		}))(w, r)
	case http.MethodGet:
		// Only apply Auth for GET
		api_sec.Auth(func(w http.ResponseWriter, r *http.Request, claims *api_sec.Claims) {
			handler(w, r, claims) // Pass claims to the handler
		})(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func main() {
	fmt.Println("Server's up!")
	loadEnv() //Load environment variables from the .env file

	//Access environment variable
	jwtSecret := os.Getenv("JWT_SECRET_KEY")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET_KEY is not set in environment variables")
	}

	api_sec.SetJWTKey(jwtSecret)

	//Define routes, apply required middleware and associate them with api functions
	http.HandleFunc("/register", api_sec.LogMiddleware(api_sec.ContentTypeJSON(api_sec.Register)))
	http.HandleFunc("/login", api_sec.LogMiddleware(api_sec.ContentTypeJSON(api_sec.Login)))

	http.HandleFunc("/accounts", api_sec.LogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		MethodRouter(w, r, api_sec.AccountsHandler)
	}))
	http.HandleFunc("/balance", api_sec.LogMiddleware(func(w http.ResponseWriter, r *http.Request) {
		MethodRouter(w, r, api_sec.BalanceHandler)
	}))

	log.Fatal(http.ListenAndServe(":8080", nil)) //starts an HTTP server that listen and serve on port 8080
}
