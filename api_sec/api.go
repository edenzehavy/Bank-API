package api_sec

import (
	"encoding/json"
	"net/http"

	"strconv"
	"strings"
	"time"

	// "log"
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

// Get all users for admins
func GetUsers(w http.ResponseWriter, r *http.Request, claims *Claims) {
	if claims.Role != "admin" {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	json.NewEncoder(w).Encode(users)
}

func AccountsHandler(w http.ResponseWriter, r *http.Request, claims *Claims) {
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
	json.NewEncoder(w).Encode(accounts)
}

func BalanceHandler(w http.ResponseWriter, r *http.Request, claims *Claims) {
	r.Body = http.MaxBytesReader(w, r.Body, 1048576) //Limit request body to 1MB
	defer r.Body.Close()

	switch r.Method {
	case http.MethodGet:
		getBalance(w, r, claims)
	//Makes sure only users can modify the balance
	case http.MethodPost:
		if claims.Role == "user" {
			ContentTypeJSON(depositBalance(w, r, claims))
		}
		http.Error(w, "Unauthorized", http.StatusForbidden)
	case http.MethodDelete:
		if claims.Role == "user" {
			withdrawBalance(w, r, claims)
		}
		http.Error(w, "Unauthorized", http.StatusForbidden)
	}
}

func getBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
	userId := r.URL.Query().Get("user_id")
	//Validating the request contains an user ID
	if userId == "" {
		http.Error(w, "Missing ID", http.StatusBadRequest)
		return
	}

	//Since Auth is validating that the request's Id matches the jwt's id,
	//we can use claims.UserID for comapring
	for _, acc := range accounts {
		if acc.UserID == claims.UserID {
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
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		next(w, r)
	}
}

func Auth(next func(http.ResponseWriter, *http.Request, *Claims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		if tokenStr == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}
		tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		//This section ensures that only users with valid claims can access the resource.
		//it checks that for regular users: the `user_id` in the request matches the `user_id` in the token claims.
		//if the request is made by an admin: there's no need for this claim check, as admins have broader access.
		//however, admins are restricted to certain operations so any further specific authorization for admins
		//will be handled inside the individual handler function.
		//if the `user_id` in the request does not match the user’s claim or is invalid,
		//an unauthorized error is returned.
		if claims.Role != "admin" {
			userIDParam := r.URL.Query().Get("user_id")
			if userIDParam != "" {
				userID, err := strconv.Atoi(r.URL.Query().Get("user_id"))
				if err != nil || userID != claims.UserID {
					http.Error(w, "Unauthorized access to resource", http.StatusForbidden)
					return
				}
			}
		}

		next(w, r, claims)
	}
}
