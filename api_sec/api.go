package api_sec

import (
	"encoding/json"
	"net/http"

	"bytes"
	"io"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Replaced the original jwtKey with an environment variable so it won't be visible through the code
var jwtKey []byte

// SetJWTKey configures the JWT key globally
func SetJWTKey(secret string) {
	jwtKey = []byte(secret)
}

type Claims struct {
	//Added UserID to ensure that the user accessing or modifying a resource is the owner of that resource
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

func Register(w http.ResponseWriter, r *http.Request) {
	//Limit request body to 1MB
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	defer r.Body.Close()

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//Validate that all required fields are provided
	if user.Username == "" {
		http.Error(w, "Missing username", http.StatusBadRequest)
		return
	}
	if user.Password == "" {
		http.Error(w, "Missing password", http.StatusBadRequest)
		return
	}
	if user.Role == "" {
		http.Error(w, "Missing role", http.StatusBadRequest)
		return
	}

	user.ID = len(users) + 1
	users = append(users, user)
	json.NewEncoder(w).Encode(user)
}

func Login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1048576) //Limit request body to 1MB
	defer r.Body.Close()

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var creds User
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//Validate that all required fields are provided
	if creds.Username == "" {
		http.Error(w, "Missing Username", http.StatusBadRequest)
		return
	}
	if creds.Password == "" {
		http.Error(w, "Missing Password", http.StatusBadRequest)
		return
	}

	// Authenticate user
	var authenticatedUser *User
	for _, user := range users {
		if user.Username == creds.Username && user.Password == creds.Password {
			authenticatedUser = &user
			break
		}
	}
	if authenticatedUser == nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &Claims{
		UserID:   authenticatedUser.ID, //Sets user's Id
		Username: authenticatedUser.Username,
		Role:     authenticatedUser.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func AccountsHandler(w http.ResponseWriter, r *http.Request, claims *Claims) {
	r.Body = http.MaxBytesReader(w, r.Body, 1048576) //Limit request body to 1MB
	defer r.Body.Close()

	//Only admins can send accounts requests
	if claims.Role != "admin" {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodPost {
		createAccount(w, r, claims)
		return
	}

	if r.Method == http.MethodGet {
		listAccounts(w, r, claims)
		return
	}
}

func createAccount(w http.ResponseWriter, r *http.Request, claims *Claims) {
	var acc Account
	if err := json.NewDecoder(r.Body).Decode(&acc); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//Validate that all required fields are provided
	if acc.UserID == 0 {
		http.Error(w, "Missing UserID", http.StatusBadRequest)
		return
	}
	if acc.Balance < 0.0 {
		http.Error(w, "Balance can not be negative", http.StatusBadRequest)
		return
	}

	//Checks that a user with the UserID specified in the query exists.
	for _, user := range users {
		if user.ID == acc.UserID {
			acc.ID = len(accounts) + 1
			acc.CreatedAt = time.Now()
			accounts = append(accounts, acc)
			json.NewEncoder(w).Encode(acc)
			return
		}
	}

	//Can't create accound for not exisiting users
	http.Error(w, "No User with the specified ID", http.StatusBadRequest)

}

func listAccounts(w http.ResponseWriter, r *http.Request, claims *Claims) {
	if claims.Role != "admin" {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	json.NewEncoder(w).Encode(users)
}

func BalanceHandler(w http.ResponseWriter, r *http.Request, claims *Claims) {
	log.Println("Reached Balance Handler")
	r.Body = http.MaxBytesReader(w, r.Body, 1048576) //Limit request body to 1MB
	defer r.Body.Close()

	switch r.Method {
	case http.MethodGet:
		getBalance(w, r, claims)

	//Makes sure all roles can only modify their own balance
	//users passed this check in Auth but this one is for admin accounts
	//wanting to deposit or withdraw from their account. they cannot do this to other users accounts.
	case http.MethodPost, http.MethodDelete:
		// POST and DELETE methods need request body
		r.Body = http.MaxBytesReader(w, r.Body, 1048576) // Limit request body to 1MB
		defer r.Body.Close()

		var acc Account
		if err := json.NewDecoder(r.Body).Decode(&acc); err != nil {
			log.Println("Error decoding in balance handler")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if claims.UserID != acc.UserID {
			http.Error(w, "Unauthorized", http.StatusForbidden)
			return
		}

		if r.Method == http.MethodPost {
			depositBalance(w, r, claims)
		} else {
			withdrawBalance(w, r, claims)
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func getBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
	userId := r.URL.Query().Get("user_id")
	//Validating the request contains an user ID
	if userId == "" {
		http.Error(w, "Missing ID", http.StatusBadRequest)
		return
	}

	userID, err := strconv.Atoi(userId)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	//Since Auth is validating that the request's Id matches the jwt's id,
	//we can use claims.UserID for comapring
	for _, acc := range accounts {
		if acc.UserID == userID {
			json.NewEncoder(w).Encode(map[string]float64{"balance": acc.Balance})
			return
		}
	}
	http.Error(w, "Account not found", http.StatusNotFound)
}

func depositBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
	var body struct {
		UserID int     `json:"user_id"`
		Amount float64 `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//Validating the request contains an user ID
	if body.UserID == 0 {
		http.Error(w, "Missing ID", http.StatusBadRequest)
		return
	}
	if body.Amount < 0 {
		http.Error(w, "Can not deposit negative amounts", http.StatusBadRequest)
		return
	}

	//Since Auth is validating that the request's Id matches the jwt's id,
	//we can use claims.UserID for comapring
	for i, acc := range accounts {
		if acc.UserID == claims.UserID {
			accounts[i].Balance += body.Amount
			json.NewEncoder(w).Encode(accounts[i])
			return
		}
	}
	http.Error(w, "Account not found", http.StatusNotFound)
}

func withdrawBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
	var body struct {
		UserID int     `json:"user_id"`
		Amount float64 `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//Validating the request contains an user ID
	if body.UserID == 0 {
		http.Error(w, "Missing ID", http.StatusBadRequest)
		return
	}

	if body.Amount < 0 {
		http.Error(w, "Can not withdraw negative amounts", http.StatusBadRequest)
		return
	}

	for i, acc := range accounts {
		//if acc.UserID == body.UserID
		if acc.UserID == claims.UserID {
			if acc.Balance < body.Amount {
				http.Error(w, ErrInsufficientFunds.Error(), http.StatusBadRequest)
				return
			}
			accounts[i].Balance -= body.Amount
			json.NewEncoder(w).Encode(accounts[i])
			return
		}
	}
	http.Error(w, "Account not found", http.StatusNotFound)
}

// Middleware for checking that the body of the request is of type JSON
func ContentTypeJSON(next http.HandlerFunc) http.HandlerFunc {
	log.Println("Reached JSON middleware")
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		next(w, r)
	}
}

func Auth(next func(http.ResponseWriter, *http.Request, *Claims)) http.HandlerFunc {
	log.Println("Reached Auth middleware")
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		if tokenStr == "" {
			log.Println("1")
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}
		tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			log.Println("2")
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			log.Println("3")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		//This section ensures that only users with valid claims can access the resource.
		//it checks that for regular users: the `user_id` in the request matches the `user_id` in the token claims.
		//if the request is made by an admin: there's no need for this claim check, as admins have broader access.
		//however, admins are restricted to certain operations so any further specific authorization for admins
		//will be handled inside the individual handler function.
		//if the `user_id` in the request (body or url) does not match the user’s claim or is invalid,
		//an unauthorized error is returned.

		if claims.Role != "admin" {
			log.Println("4")
			userIDParam := r.URL.Query().Get("user_id")
			if userIDParam != "" {
				userID, err := strconv.Atoi(userIDParam)
				if err != nil || userID != claims.UserID {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}

			var bodyData struct {
				UserID int `json:"user_id"`
			}

			//Check user id in the json body for post and delete requests
			if r.Method == http.MethodPost || r.Method == http.MethodDelete {
				bodyBytes, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, "Invalid request body", http.StatusBadRequest)
					return
				}

				//Reassign body to allow later handlers to read it
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

				//Decode body into struct
				if err := json.Unmarshal(bodyBytes, &bodyData); err == nil && bodyData.UserID != 0 {
					if bodyData.UserID != claims.UserID {
						http.Error(w, "Unauthorized", http.StatusUnauthorized)
						return
					}
				} else if err != nil {
					http.Error(w, "Invalid request body", http.StatusBadRequest)
					return
				}
			}
		}

		log.Println("called next function from auth")
		next(w, r, claims)

	}
}
