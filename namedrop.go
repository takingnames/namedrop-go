package namedrop

import (
	"crypto/rand"
	"math/big"
)

type TokenData struct {
	Owner  string  `json:"owner"`
	Scopes []Scope `json:"scopes"`
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
