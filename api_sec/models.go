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

// // custom method to handle both "UserID" and "user_id"
// func (a *Account) UnmarshalJSON(data []byte) error {
// 	var decodedAccount struct {
// 		ID        int       `json:"ID"`
// 		UserID    int       `json:"UserID"`
// 		UserIDAlt int       `json:"user_id"`
// 		Balance   float64   `json:"value"`
// 		CreatedAt time.Time `json:"CreatedAt"`
// 	}

// 	//decode into the struct
// 	if err := json.Unmarshal(data, &decodedAccount); err != nil {
// 		return err
// 	}

// 	//assign fields to the Account struct
// 	a.ID = decodedAccount.ID
// 	a.Balance = decodedAccount.Balance
// 	a.CreatedAt = decodedAccount.CreatedAt

// 	//handle UserID from multiple possible json keys since
// 	//a post request to /accounts requires "UserID" in it's body
// 	//and post and delete requests to /balance requires "user_id" in it's body
// 	if decodedAccount.UserID != 0 {
// 		a.UserID = decodedAccount.UserID
// 	} else if decodedAccount.UserIDAlt != 0 {
// 		a.UserID = decodedAccount.UserIDAlt
// 	} else {
// 		return errors.New("missing required field: UserID or user_id")
// 	}

// 	return nil
// }

var users []User
var accounts []Account

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrAccountNotFound   = errors.New("account not found")
	ErrInsufficientFunds = errors.New("insufficient funds")
)
