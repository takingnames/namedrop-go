package namedrop

import (
	//"fmt"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	oauth "github.com/anderspitman/little-oauth2-go"
)

type Database interface {
	SetToken(token string, tokenData *TokenData)
	GetToken(token string) (*TokenData, error)
	SetPendingToken(code string, tok PendingToken)
	GetPendingToken(code string) (PendingToken, error)
}

type Server struct {
	db  Database
	mux *http.ServeMux
}

type PendingToken struct {
	AuthRequestState string
}

type AuthRequest = oauth.AuthRequest

func NewServer(db Database) *Server {

	a := &Server{
		db: db,
	}

	mux := &http.ServeMux{}

	mux.HandleFunc("/token", a.handleToken)
	mux.HandleFunc("/token-data", a.handleTokenData)
	mux.HandleFunc("/my-ip", func(w http.ResponseWriter, r *http.Request) {
		ip := ReadRemoteIp(r)
		io.WriteString(w, ip)
	})

	a.mux = mux

	return a
}

func (a *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

func (a *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	grantType := r.Form.Get("grant_type")

	var refreshToken string
	var err error

	if grantType == "authorization_code" {
		codeData, err := a.db.GetPendingToken(r.Form.Get("code"))
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		refreshToken, err = oauth.ParseTokenRequest(r.Form, codeData.AuthRequestState)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	} else if grantType == "refresh_token" {
		refreshToken, err = oauth.ParseRefreshRequest(r.Form)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	}

	tokenData, err := a.db.GetToken(refreshToken)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	// TODO: make sure token is valid

	// TODO: set IssuedAt to current time
	//tokenData.IssuedAt =
	tokenData.ExpiresIn = 3600

	accessToken, _ := genRandomKey()
	a.db.SetToken(accessToken, tokenData)

	resp := oauth.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
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

func (a *Server) handleTokenData(w http.ResponseWriter, r *http.Request) {
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

func ParseAuthRequest(params url.Values) (*AuthRequest, error) {

	req, err := oauth.ParseAuthRequest(params)
	if err != nil {
		return nil, err
	}

	parsedClientIdUri, err := url.Parse(req.ClientId)
	if err != nil {
		msg := "client_id is not a valid URI"
		return nil, errors.New(msg)
	}

	parsedRedirectUri, err := url.Parse(req.RedirectUri)
	if err != nil {
		msg := "redirect_uri is not a valid URI"
		return nil, errors.New(msg)
	}

	// draft-ietf-oauth-security-topics-24 4.1
	if parsedClientIdUri.Host != parsedRedirectUri.Host {
		return nil, errors.New("redirect_uri must be on the same domain as client_id")
	}

	return req, nil
}

func (a *Server) CreateCode(tokenData *TokenData, authReqParams string) string {

	token, _ := genRandomKey()

	a.db.SetToken(token, tokenData)

	code, _ := genRandomKey()

	authReqState := oauth.EncodeAuthRequestState(token, authReqParams)

	pendingToken := PendingToken{
		AuthRequestState: authReqState,
	}

	a.db.SetPendingToken(code, pendingToken)

	return code
}

func (a *Server) Authorized(r *http.Request) (*Record, error) {
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

func ReadRemoteIp(r *http.Request) string {

	xffHeader := r.Header.Get("X-Forwarded-For")

	var ip string

	if xffHeader != "" {
		xff := strings.Split(xffHeader, ",")
		ip = strings.TrimSpace(xff[0])
	} else {
		// TODO: Handle ipv6
		addrParts := strings.Split(r.RemoteAddr, ":")
		ip = addrParts[0]
	}

	return ip
}
