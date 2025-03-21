package namedrop

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	oauth "github.com/anderspitman/little-oauth2-go"
	"github.com/libdns/libdns"
)

const ScopeHosts = "namedrop-hosts"
const ScopeMail = "namedrop-mail"
const ScopeAcme = "namedrop-acme"
const ScopeAtprotoHandle = "namedrop-atproto-handle"
const ScopeWeirdHandle = "namedrop-weird-handle"

func validScope(s string) bool {
	return s == ScopeHosts || s == ScopeMail || s == ScopeAcme || s == ScopeAtprotoHandle || s == ScopeWeirdHandle
}

type Error struct {
	Message    string
	StatusCode int
}

func (e *Error) Error() string {
	return e.Message
}

type SuccessResponse struct {
	Type    string    `json:"type"`
	Records []*Record `json:"records"`
}

type ErrorResponse struct {
	Type   string                 `json:"type"`
	Errors []*RecordErrorResponse `json:"errors"`
}

type RecordErrorResponse struct {
	Message            string    `json:"message"`
	RequestedRecord    *Record   `json:"requested_record"`
	ConflictingRecords []*Record `json:"conflicting_records,omitempty"`
}

type KvStore interface {
	Get(key string) (value []byte, err error)
	Set(key string, value []byte) (err error)
	Delete(key string) (err error)
}

type DnsProvider interface {
	libdns.ZoneLister
	libdns.RecordGetter
	libdns.RecordSetter
	libdns.RecordDeleter
}

type RecordsRequest struct {
	Domain            string    `json:"domain"`
	Host              string    `json:"host"`
	Token             string    `json:"token"`
	Records           []*Record `json:"records"`
	DeleteConflicting bool      `json:"delete_conflicting"`
}

type AuthRequest struct {
	*oauth.AuthRequest
	RequestedPermissions []*Permission
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
	Id       string `json:"id,omitempty"`
	Domain   string `json:"domain"`
	Host     string `json:"host"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	TTL      uint32 `json:"ttl"`
	Priority uint   `json:"priority,omitempty"`
	Weight   int    `json:"weight,omitempty"`
}

type TokenResponse struct {
	oauth.TokenResponse
	Permissions []*Permission `json:"permissions"`
}

func GenRandomKey() (string, error) {
	return genRandomKey()
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
			return p.Scope == ScopeMail && commonChecks(r, p)
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
			return p.Scope == ScopeAcme && commonChecks(r, p)
		}

		if strings.HasPrefix(r.Host, "_atproto") {
			return p.Scope == ScopeAtprotoHandle &&
				strings.HasPrefix(r.Value, "did=") && commonChecks(r, p)
		}

		if strings.HasPrefix(r.Host, "_weird") {
			return p.Scope == ScopeWeirdHandle &&
				strings.HasPrefix(r.Value, "subspace=") && commonChecks(r, p)
		}

		trimmedValue := strings.TrimSpace(r.Value)
		if strings.HasPrefix(trimmedValue, "v=spf1") {
			return p.Scope == ScopeMail && commonChecks(r, p)
		}

		domainParts := strings.Split(r.Host, ".")
		if len(domainParts) > 1 && domainParts[1] == "_domainkey" {
			return p.Scope == ScopeMail && commonChecks(r, p)
		}

		return false

	default:
		return false
	}

	return commonChecks(r, p)
}

func commonChecks(r *Record, p *Permission) bool {
	return r.Domain == p.Domain && strings.HasSuffix(r.Host, p.Host)
}

func BuildPermDescriptions(requestedPerms []*Permission) (descriptions []string, err error) {

	descriptions = []string{}

	for _, perm := range requestedPerms {

		var description string

		switch perm.Scope {
		case ScopeHosts:
			description = "Change the servers domain points to"
		case ScopeMail:
			description = "Change mail servers and settings for domain"
		case ScopeAcme:
			description = "Obtain security (TLS) certificates for domain"
		case ScopeAtprotoHandle:
			description = "Set domain as your Bluesky/atproto handle"
		case ScopeWeirdHandle:
			description = "Set domain as your Weird handle"
		default:
			errors.New("Unknown scope " + perm.Scope)
			return
		}

		descriptions = append(descriptions, description)
	}

	return descriptions, nil
}

func printJson(data interface{}) {
	d, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(d))
}
