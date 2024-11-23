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

func main() {
	fmt.Println("Server's up!")
	loadEnv() //Load environment variables from the .env file

	//Access environment variable
	jwtSecret := os.Getenv("JWT_SECRET_KEY")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET_KEY is not set in environment variables")
	}

	api_sec.SetJWTKey(jwtSecret)

	//Define routes and associate them with api functions
	http.HandleFunc("/register", api_sec.ContentTypeJSON(api_sec.Register))
	http.HandleFunc("/login", api_sec.ContentTypeJSON(api_sec.Login))
	http.HandleFunc("/accounts", api_sec.ContentTypeJSON(api_sec.Auth(api_sec.AccountsHandler)))
	http.HandleFunc("/balance", api_sec.Auth(api_sec.BalanceHandler))
	http.HandleFunc("/users", api_sec.Auth(api_sec.GetUsers))

	log.Fatal(http.ListenAndServe(":8080", nil)) //Listen and serve on port 8080
}
