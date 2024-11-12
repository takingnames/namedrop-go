package namedrop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	oauth "github.com/anderspitman/little-oauth2-go"
	"github.com/libdns/libdns"
)

type Server struct {
	store       KvStore
	dnsProvider DnsProvider
	mux         *http.ServeMux
}

func NewServer(store KvStore, dnsProvider DnsProvider) *Server {

	a := &Server{
		store:       store,
		dnsProvider: dnsProvider,
	}

	mux := &http.ServeMux{}

	mux.HandleFunc("/token", a.handleToken)
	mux.HandleFunc("/token-data", a.handleTokenData)
	mux.HandleFunc("/my-ip", func(w http.ResponseWriter, r *http.Request) {
		ip := ReadRemoteIp(r)
		io.WriteString(w, ip)
	})
	mux.HandleFunc("/set-records", a.handleRecords)

	a.mux = mux

	return a
}

func (a *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

func (a *Server) handleRecords(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Max-Age", "99999")
		return
	}

	var req *RecordsRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	expandedReq, err := a.Authorized(req)
	if err != nil {
		if e, ok := err.(*Error); ok {
			http.Error(w, err.Error(), e.StatusCode)
		} else {
			http.Error(w, err.Error(), 400)
		}
		return
	}

	errors := []*RecordErrorResponse{}
	mu := &sync.Mutex{}
	wg := sync.WaitGroup{}

	switch r.URL.Path {
	case "/set-records":

		records := []libdns.Record{}
		for _, rec := range expandedReq.Records {
			wg.Add(1)
			go func(rec *Record) {

				defer wg.Done()

				record := libdns.Record{
					Type:     rec.Type,
					Name:     rec.Host,
					Value:    rec.Value,
					TTL:      time.Second * time.Duration(rec.TTL),
					Priority: uint(rec.Priority),
					Weight:   uint(rec.Weight),
				}
				records = append(records, record)

				// TODO: handle requests with records for multiple zones
				zone := expandedReq.Records[0].Domain
				_, err = a.dnsProvider.SetRecords(context.Background(), zone, records)
				if err != nil {
					ndErr := &RecordErrorResponse{
						Message: err.Error(),
						Record:  rec,
					}

					mu.Lock()
					errors = append(errors, ndErr)
					mu.Unlock()
				}
			}(rec)
		}
	}

	wg.Wait()

	if len(errors) > 0 {
		w.WriteHeader(400)
		err = json.NewEncoder(w).Encode(&ErrorResponse{
			Type:   "error",
			Errors: errors,
		})

		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		return
	}

	err = json.NewEncoder(w).Encode(&SuccessResponse{
		Type:    "success",
		Records: expandedReq.Records,
	})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}

func (a *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	w.Header().Set("Access-Control-Allow-Origin", "*")

	grantType := r.Form.Get("grant_type")

	var refreshToken string
	var err error

	if grantType == "authorization_code" {

		code := r.Form.Get("code")

		codeData := new(PendingToken)
		found, err := a.store.Get("pending_tokens/"+code, codeData)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		if !found {
			http.Error(w, "No such pending token", 400)
			return
		}

		refreshToken, err = oauth.VerifyTokenRequest(r.Form, codeData.AuthRequestState)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		err = a.store.Delete("pending_tokens/" + code)
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

	tokenData := new(TokenData)
	found, err := a.store.Get("token_data/"+refreshToken, tokenData)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	if !found {
		http.Error(w, "Token data not found", 400)
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

	err = a.store.Set("token_data/"+accessToken, tokenData)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

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

	tokenData := new(TokenData)
	found, err := a.store.Get("token_data/"+token, tokenData)
	if err != nil {
		w.WriteHeader(400)
		io.WriteString(w, err.Error())
		return
	}

	if !found {
		http.Error(w, "No such token", 400)
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

	reqPerms, err := scopesToPerms(req.Scopes)
	if err != nil {
		return nil, err
	}

	ar := &AuthRequest{
		AuthRequest:          req,
		RequestedPermissions: reqPerms,
	}

	return ar, nil
}

func (a *Server) CreateCode(tokenData *TokenData, authReqParams string) (string, error) {

	token, err := genRandomKey()
	if err != nil {
		return "", err
	}

	tokenData.Token = token
	tokenData.IssuedAt = time.Now().UTC()
	tokenData.ExpiresIn = 0

	err = a.store.Set("token_data/"+token, tokenData)
	if err != nil {
		return "", err
	}

	code, err := genRandomKey()
	if err != nil {
		return "", err
	}

	authReqState := oauth.EncodeAuthRequestState(token, authReqParams)

	pendingToken := PendingToken{
		AuthRequestState: authReqState,
	}

	err = a.store.Set("pending_tokens/"+code, pendingToken)
	if err != nil {
		return "", err
	}

	return code, nil
}

func (a *Server) Authorized(request *RecordsRequest) (*RecordsRequest, error) {

	tokenData := new(TokenData)
	found, err := a.store.Get("token_data/"+request.Token, tokenData)
	if err != nil {
		return nil, err
	}

	if !found {
		return nil, errors.New("No such token")
	}

	if oauth.Expired(tokenData.IssuedAt, tokenData.ExpiresIn) {
		// TODO: delete token
		return nil, &Error{
			Message:    "Token expired",
			StatusCode: 403,
		}
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
		cp.Host = strings.Replace(cp.Host, "{{host}}", expandedReq.Host, -1)
		if strings.HasSuffix(cp.Host, ".") {
			cp.Host = cp.Host[:len(cp.Host)-1]
		}
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

		return nil, &Error{
			Message:    "Insufficient permissions",
			StatusCode: 403,
		}
	} else {
		for _, record := range expandedReq.Records {
			if !hasPerm(record, tokenData.Permissions) {
				return nil, &Error{
					Message:    "Insufficient permissions",
					StatusCode: 403,
				}
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
