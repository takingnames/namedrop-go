package namedrop

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	oauth "github.com/anderspitman/little-oauth2-go"
)

const ScopeHosts = "namedrop-hosts"
const ScopeMail = "namedrop-mail"
const ScopeAcme = "namedrop-acme"

type AuthRequest struct {
	*oauth.AuthRequest
	RequestedPermissions []*Permission
}

type Database interface {
	SetTokenData(tokenData *TokenData)
	GetTokenData(token string) (*TokenData, error)
	SetPendingToken(code string, tok PendingToken)
	GetPendingToken(code string) (PendingToken, error)
	DeletePendingToken(code string) error
}

type TokenData struct {
	Token       string        `json:"token" db:"token"`
	OwnerId     string        `json:"owner_id" db:"owner_id"`
	Permissions []*Permission `json:"permissions" db:"permissions"`
	IssuedAt    time.Time     `json:"issued_at" db:"issued_at"`
	ExpiresIn   int           `json:"expires_in" db:"expires_in"`
}

type PendingToken struct {
	AuthRequestState string
}

type Scope struct {
	Domain string `json:"domain"`
	Host   string `json:"host"`
}

type Permission struct {
	Scope  string `json:"scope"`
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
	Permissions []*Permission `json:"permissions"`
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

func hasPerm(record *Record, perms []*Permission) bool {
	for _, perm := range perms {
		if checkPerm(record, perm) {
			return true
		}
	}

	return false
}

func checkPerm(r *Record, p *Permission) bool {
	switch r.Type {
	case "A":
		fallthrough
	case "AAAA":
		fallthrough
	case "ANAME":
		fallthrough
	case "CNAME":

		domainParts := strings.Split(r.Host, ".")
		if len(domainParts) > 1 && domainParts[1] == "_domainkey" {
			return p.Scope == ScopeMail && r.Domain == p.Domain
		}

		if p.Scope != ScopeHosts {
			return false
		}

	case "MX":
		if p.Scope != ScopeMail {
			return false
		}
	case "TXT":
		if strings.HasPrefix(r.Host, "_acme-challenge") {
			return p.Scope == ScopeAcme && r.Domain == p.Domain
		}

		trimmedValue := strings.TrimSpace(r.Value)
		if strings.HasPrefix(trimmedValue, "v=spf1") {
			return p.Scope == ScopeMail
		}

		domainParts := strings.Split(r.Host, ".")
		if len(domainParts) > 1 && domainParts[1] == "_domainkey" {
			return p.Scope == ScopeMail && r.Domain == p.Domain
		}

		return false

	default:
		return false
	}

	return r.Domain == p.Domain && r.Host == p.Host
}

func printJson(data interface{}) {
	d, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(d))
}
