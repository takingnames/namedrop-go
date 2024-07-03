package namedrop

import (
	"crypto/rand"
	"math/big"

	oauth "github.com/anderspitman/little-oauth2-go"
)

type AuthRequest = oauth.AuthRequest

type Database interface {
	SetToken(token string, tokenData *TokenData)
	GetToken(token string) (*TokenData, error)
	SetPendingToken(code string, tok PendingToken)
	GetPendingToken(code string) (PendingToken, error)
}

type TokenData struct {
	OwnerId   string  `json:"owner_id"`
	Scopes    []Scope `json:"scopes"`
	IssuedAt  int     `json:"issued_at"`
	ExpiresIn int     `json":expires_in"`
}

type PendingToken struct {
	AuthRequestState string
}

type Scope struct {
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
