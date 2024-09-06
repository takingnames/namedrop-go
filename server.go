package namedrop

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	oauth "github.com/anderspitman/little-oauth2-go"
)

type Server struct {
	db  Database
	mux *http.ServeMux
}

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

	w.Header().Set("Access-Control-Allow-Origin", "*")

	grantType := r.Form.Get("grant_type")

	var refreshToken string
	var err error

	if grantType == "authorization_code" {

		code := r.Form.Get("code")

		codeData, err := a.db.GetPendingToken(code)
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

		err = a.db.DeletePendingToken(code)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	} else {
		refreshToken, err = oauth.ParseRefreshRequest(r.Form)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	}

	tokenData, err := a.db.GetTokenData(refreshToken)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	if tokenData.ExpiresIn != 0 {
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, "Attempted to use non-refresh token to refresh")
			return
		}
	}

	tokenData.IssuedAt = time.Now().UTC()
	expiresInSeconds := 3600
	tokenData.ExpiresIn = expiresInSeconds

	accessToken, _ := genRandomKey()
	tokenData.Token = accessToken
	a.db.SetTokenData(tokenData)

	resp := TokenResponse{
		oauth.TokenResponse{
			AccessToken:  accessToken,
			TokenType:    "bearer",
			ExpiresIn:    expiresInSeconds,
			RefreshToken: refreshToken,
		},
		tokenData.Permissions,
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

	tokenData, err := a.db.GetTokenData(token)
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

	perms := strings.Split(req.Scope, " ")
	reqPerms, err := scopesToPerms(perms)
	if err != nil {
		return nil, err
	}

	ar := &AuthRequest{
		AuthRequest:          req,
		RequestedPermissions: reqPerms,
	}

	return ar, nil
}

func (a *Server) CreateCode(tokenData *TokenData, authReqParams string) string {

	token, _ := genRandomKey()

	tokenData.Token = token
	tokenData.IssuedAt = time.Now().UTC()
	tokenData.ExpiresIn = 0

	a.db.SetTokenData(tokenData)

	code, _ := genRandomKey()

	authReqState := oauth.EncodeAuthRequestState(token, authReqParams)

	pendingToken := PendingToken{
		AuthRequestState: authReqState,
	}

	a.db.SetPendingToken(code, pendingToken)

	return code
}

func (a *Server) Authorized(request *RecordsRequest) (*RecordsRequest, error) {

	tokenData, err := a.db.GetTokenData(request.Token)
	if err != nil {
		return nil, err
	}

	if oauth.Expired(tokenData.IssuedAt, tokenData.ExpiresIn) {
		// TODO: delete token
		return nil, errors.New("Token expired")
	}

	expandedReq := &RecordsRequest{}

	expandedReq.Domain = request.Domain
	if expandedReq.Domain == "" {
		tokDomainMap := make(map[string]bool)

		for _, perm := range tokenData.Permissions {
			tokDomainMap[perm.Domain] = true
		}

		if len(tokDomainMap) == 1 {
			expandedReq.Domain = tokenData.Permissions[0].Domain
		}
	}

	expandedReq.Host = request.Host
	if expandedReq.Host == "" {
		tokHostMap := make(map[string]bool)

		for _, perm := range tokenData.Permissions {
			tokHostMap[perm.Host] = true
		}

		if len(tokHostMap) == 1 {
			expandedReq.Host = tokenData.Permissions[0].Host
		}
	}

	recsCopy := make([]*Record, len(request.Records))
	for i, rec := range request.Records {
		cp := *rec
		recsCopy[i] = &cp
	}

	expandedReq.Records = recsCopy

	for _, rec := range recsCopy {
		if rec.Domain == "" {
			rec.Domain = expandedReq.Domain
		}
		if rec.Host == "" {
			rec.Host = expandedReq.Host
		}
	}

	if expandedReq.Records == nil {
		// get-records request
		for _, perm := range tokenData.Permissions {
			if expandedReq.Domain == perm.Domain && expandedReq.Host == perm.Host {
				return nil, nil
			}
		}

		return nil, errors.New("Insufficient perms")
	} else {
		for _, record := range expandedReq.Records {
			if !hasPerm(record, tokenData.Permissions) {
				return nil, errors.New("Insufficient perms")
			}
		}
	}

	return expandedReq, nil
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

func scopesToPerms(scopes []string) ([]*Permission, error) {

	reqPerms := []*Permission{}

	for _, scope := range scopes {

		if !validScope(scope) {
			return nil, fmt.Errorf("Invalid scope '%s'\n", scope)
		}

		reqPerm := &Permission{
			Scope: scope,
		}

		reqPerms = append(reqPerms, reqPerm)
	}

	return reqPerms, nil
}

func validScope(s string) bool {
	return s == ScopeHosts || s == ScopeMail || s == ScopeAcme
}
