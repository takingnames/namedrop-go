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
	mux.HandleFunc("/get-records", a.handleRecords)
	mux.HandleFunc("/set-records", a.handleRecords)
	mux.HandleFunc("/delete-records", a.handleRecords)

	mux.HandleFunc("/temp-subdomain", a.handleTempDomain)
	mux.HandleFunc("/ip-domain", a.handleTempDomain)

	a.mux = mux

	return a
}

func (a *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

func (a *Server) handleRecords(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()

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

	resultRecords := []*Record{}

	existingRecs, err := a.dnsProvider.GetRecords(context.Background(), expandedReq.Domain)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	switch r.URL.Path {
	case "/get-records":
		for _, r := range existingRecs {
			resultRecords = append(resultRecords, libdnsToNamedrop(r, req.Domain))
		}
	case "/set-records":

		for _, rec := range expandedReq.Records {

			wg.Add(1)
			go func(rec *Record) {
				defer wg.Done()

				conflicts := findConflicting(rec, existingRecs)

				if len(conflicts) > 0 {
					if req.DeleteConflicting {
						_, err = a.dnsProvider.DeleteRecords(context.Background(), rec.Domain, conflicts)
						if err != nil {
							ndErr := &RecordErrorResponse{
								Message:         err.Error(),
								RequestedRecord: rec,
							}

							mu.Lock()
							errors = append(errors, ndErr)
							mu.Unlock()

							return
						}
					} else {
						resConflicts := []*Record{}
						for _, c := range conflicts {
							resConflicts = append(resConflicts, libdnsToNamedrop(c, rec.Domain))
						}
						ndErr := &RecordErrorResponse{
							Message:            "Conflicts detected",
							RequestedRecord:    rec,
							ConflictingRecords: resConflicts,
						}

						mu.Lock()
						errors = append(errors, ndErr)
						mu.Unlock()

						return
					}
				}

				record := namedropToLibdns(rec)
				records := []libdns.Record{record}

				_, err = a.dnsProvider.SetRecords(context.Background(), rec.Domain, records)
				if err != nil {
					ndErr := &RecordErrorResponse{
						Message:         err.Error(),
						RequestedRecord: rec,
					}

					mu.Lock()
					errors = append(errors, ndErr)
					mu.Unlock()
				}
			}(rec)
		}

	case "/delete-records":
		for _, rec := range expandedReq.Records {

			wg.Add(1)
			go func(rec *Record) {
				defer wg.Done()

				matchingRecord, match := findMatching(rec, existingRecs)
				if !match {
					ndErr := &RecordErrorResponse{
						Message:         "No matching record found",
						RequestedRecord: rec,
					}

					mu.Lock()
					errors = append(errors, ndErr)
					mu.Unlock()
					return
				}

				records := []libdns.Record{matchingRecord}

				_, err = a.dnsProvider.DeleteRecords(context.Background(), rec.Domain, records)
				if err != nil {
					ndErr := &RecordErrorResponse{
						Message:         err.Error(),
						RequestedRecord: rec,
					}

					mu.Lock()
					errors = append(errors, ndErr)
					mu.Unlock()
					return
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
		Records: resultRecords,
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

func (a *Server) handleTempDomain(w http.ResponseWriter, r *http.Request) {
	ip := ReadRemoteIp(r)

	replaceChar := ":"
	recordType := "AAAA"
	if IsIPv4(ip) {
		replaceChar = "."
		recordType = "A"
	}

	host := strings.Replace(ip, replaceChar, "-", -1)

	var zone string
	found, err := a.store.Get("temp_subdomain_zone", &zone)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if !found {
		http.Error(w, "temp_subdomain_zone not found in store", 500)
		return
	}

	ctx := context.Background()

	existingRecs, err := a.dnsProvider.GetRecords(ctx, zone)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	alreadyExists := false
	for _, rec := range existingRecs {
		if rec.Name == host {
			alreadyExists = true
			break
		}
	}

	if !alreadyExists {
		rec := libdns.Record{
			Type:  recordType,
			Name:  host,
			Value: ip,
		}
		recs := []libdns.Record{rec}

		_, err := a.dnsProvider.SetRecords(ctx, zone, recs)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}

	io.WriteString(w, host+"."+zone)
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
		return nil, &Error{
			Message:    "Invalid token",
			StatusCode: 401,
		}
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

	// TODO: XFF security
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

func namedropToLibdns(rec *Record) libdns.Record {
	return libdns.Record{
		Type:     rec.Type,
		Name:     rec.Host,
		Value:    rec.Value,
		TTL:      time.Second * time.Duration(rec.TTL),
		Priority: uint(rec.Priority),
		Weight:   uint(rec.Weight),
	}
}

func libdnsToNamedrop(r libdns.Record, zone string) *Record {
	return &Record{
		Id:       r.ID,
		Domain:   zone,
		Type:     r.Type,
		Host:     r.Name,
		Value:    r.Value,
		TTL:      uint32(r.TTL.Seconds()),
		Priority: int(r.Priority),
		Weight:   int(r.Weight),
	}
}

func findConflicting(rec *Record, existingRecs []libdns.Record) []libdns.Record {
	conflicts := []libdns.Record{}

	switch rec.Type {
	case "CNAME":
		fallthrough
	case "ANAME":
		for _, er := range existingRecs {
			if rec.Host == er.Name &&
				(er.Type == "CNAME" || er.Type == "ANAME" ||
					er.Type == "A" || er.Type == "AAAA") {
				conflicts = append(conflicts, er)
			}
		}
	case "A":
		fallthrough
	case "AAAA":
		for _, er := range existingRecs {
			if rec.Host == er.Name && (er.Type == "CNAME" || er.Type == "ANAME") {
				conflicts = append(conflicts, er)
			}
		}
	default:
		for _, er := range existingRecs {
			if recordsEqual(rec, er) {
				conflicts = append(conflicts, er)
			}
		}
	}

	return conflicts
}

func findMatching(rec *Record, existingRecs []libdns.Record) (libdns.Record, bool) {
	for _, er := range existingRecs {
		if recordsEqual(rec, er) {
			return er, true
		}
	}

	return libdns.Record{}, false
}

func recordsEqual(r *Record, er libdns.Record) bool {
	return r.Type == er.Type && r.Host == er.Name && r.Value == er.Value
}

// Taken from https://stackoverflow.com/a/48519490/943814
func IsIPv4(address string) bool {
	return strings.Count(address, ":") < 2
}
