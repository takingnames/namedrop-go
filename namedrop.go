package namedrop

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
)

type Database interface {
	SetToken(token string, tokenData TokenData)
	GetToken(token string) (TokenData, error)
	SetPendingToken(code string, tok PendingToken)
	GetPendingToken(code string) (PendingToken, error)
}

type Api struct {
	db  Database
	mux *http.ServeMux
}

type AuthRequest struct {
	ClientId    string
	RedirectUri string
	Scope       string
	State       string
}

type TokenData struct {
	Owner  string  `json:"owner"`
	Scopes []Scope `json:"scopes"`
}

type Scope struct {
	Domain string `json:"domain"`
	Host   string `json:"host"`
}

type PendingToken struct {
	Token string `json:"token"`
}

type Oauth2TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

type Record struct {
	Domain   string `json:"domain"`
	Host     string `json:"host"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	TTL      uint32 `json:"ttl"`
	Priority int    `json:"priority"`
}

type CreateRecordsRequest struct {
	Records []Record
}

func NewApi(db Database) *Api {

	a := &Api{
		db: db,
	}

	mux := &http.ServeMux{}

	mux.HandleFunc("/token", a.handleToken)
	mux.HandleFunc("/token-data", a.handleTokenData)

	a.mux = mux

	return a
}

func (a *Api) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

func (a *Api) handleToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	code := r.Form.Get("code")

	codeData, err := a.db.GetPendingToken(code)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	resp := Oauth2TokenResponse{
		AccessToken: codeData.Token,
		TokenType:   "bearer",
	}

	jsonStr, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")

	w.Write(jsonStr)
}

func (a *Api) handleTokenData(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	token, err := extractToken("access_token", r)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	tokenData, err := a.db.GetToken(token)
	if err != nil {
		w.WriteHeader(400)
		io.WriteString(w, err.Error())
		return
	}

	jsonStr, err := json.MarshalIndent(tokenData, "", "  ")
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")

	w.Write(jsonStr)
}

func (a *Api) ExtractAuthRequest(r *http.Request) (*AuthRequest, error) {
	r.ParseForm()

	clientId := r.Form.Get("client_id")
	if clientId == "" {
		return nil, errors.New("Missing client_id param")
	}

	redirectUri := r.Form.Get("redirect_uri")
	if redirectUri == "" {
		return nil, errors.New("Missing redirect_uri param")
	}

	if !strings.HasPrefix(redirectUri, clientId) {
		return nil, errors.New("redirect_uri must be on the same domain as client_id")
	}

	scope := r.Form.Get("scope")
	if scope == "" {
		return nil, errors.New("Missing scope param")
	}

	state := r.Form.Get("state")
	if state == "" {
		return nil, errors.New("state param can't be empty")
	}

	req := &AuthRequest{
		ClientId:    clientId,
		RedirectUri: redirectUri,
		Scope:       scope,
		State:       state,
	}

	return req, nil
}

func (a *Api) CreateCode(tokenData TokenData) string {

	token, _ := genRandomKey()

	a.db.SetToken(token, tokenData)

	code, _ := genRandomKey()

	pendingToken := PendingToken{
		Token: token,
	}

	a.db.SetPendingToken(code, pendingToken)

	return code
}

func (a *Api) Authorized(r *http.Request) (*Record, error) {
	token, err := extractToken("access_token", r)
	if err != nil {
		return nil, err
	}

	bodyJson, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var record *Record
	err = json.Unmarshal(bodyJson, &record)
	if err != nil {
		return nil, err
	}

	tokenData, err := a.db.GetToken(token)
	if err != nil {
		return nil, err
	}

	if !hasPerm(record, tokenData.Scopes) {
		return nil, errors.New("No perms")
	}

	return record, nil
}

// TODO: Test this
func hasPerm(record *Record, scopes []Scope) bool {
	for _, scope := range scopes {
		if record.Domain != scope.Domain {
			continue
		}

		if strings.HasPrefix(scope.Host, "*") {
			if !strings.HasSuffix(record.Host, scope.Host[1:]) {
				continue
			}
		} else if record.Host != scope.Host {
			continue
		}

		return true
	}

	return false
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

func extractToken(tokenName string, r *http.Request) (string, error) {

	query := r.URL.Query()

	queryToken := query.Get(tokenName)
	if queryToken != "" {
		return queryToken, nil
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		tokenHeader := strings.Split(authHeader, " ")[1]
		return tokenHeader, nil
	}

	return "", errors.New("No token found")
}
