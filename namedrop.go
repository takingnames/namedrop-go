package namedrop

import (
	"crypto/rand"
	"math/big"
	"time"

	oauth "github.com/anderspitman/little-oauth2-go"
)

type AuthRequest = oauth.AuthRequest

type Database interface {
	SetTokenData(tokenData *TokenData)
	GetTokenData(token string) (*TokenData, error)
	SetPendingToken(code string, tok PendingToken)
	GetPendingToken(code string) (PendingToken, error)
}

type TokenData struct {
	Token     string    `json:"token" db:"token"`
	OwnerId   string    `json:"owner_id" db:"owner_id"`
	Scopes    []Scope   `json:"scopes" db:"scopes"`
	IssuedAt  time.Time `json:"issued_at" db:"issued_at"`
	ExpiresIn int       `json:"expires_in" db:"expires_in"`
}

type PendingToken struct {
	AuthRequestState string
}

type Scope struct {
	Domain string `json:"domain"`
	Host   string `json:"host"`
}

type Permission struct {
	Domain string `json:"domain"`
	Host   string `json:"host"`
}

type Record struct {
	Domain   string `json:"domain"`
	Host     string `json:"host"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	TTL      uint32 `json:"ttl"`
	Priority int    `json:"priority"`
}

type TokenResponse struct {
        oauth.TokenResponse
        Permissions []Scope `json:"permissions"`
}

func genRandomKey() (string, error) {

	const chars string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	id := ""
	for i := 0; i < 32; i++ {
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		id += string(chars[randIndex.Int64()])
	}
	return id, nil
}

func hasPerm(record *Record, scopes []Scope) bool {
	for _, scope := range scopes {
		if record.Domain == scope.Domain && record.Host == scope.Host {
			return true
		}
	}

	return false
}
