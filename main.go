package main


import (
	"fmt"
	"log"
	"os"
	"github.com/joho/godotenv"
	//imported pkg for api.go
	"f5.com/ha/pkg" 
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
	//Load environment variables from the .env file
	loadEnv()

	//Access environment variable
	jwtSecret := os.Getenv("JWT_SECRET_KEY")

	//Set the global JWT key in api_sec package
	api_sec.SetJWTKey(jwtSecret)

}
