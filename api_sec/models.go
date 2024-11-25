package api_sec

import (
	// "encoding/json"
	"errors"
	"time"
)

type User struct {
	ID       int    `json:"ID"`
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type Account struct {
	ID        int       `json:"ID"`
	UserID    int       `json:"UserID"`
	Balance   float64   `json:"value"`
	CreatedAt time.Time `json:"CreatedAt"`
}

var users []User
var accounts []Account

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrAccountNotFound   = errors.New("account not found")
	ErrInsufficientFunds = errors.New("insufficient funds")
)
