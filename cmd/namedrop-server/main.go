package main

import (
	//"time"
	//"sync"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/lastlogin-net/decent-auth-go"
	//"github.com/lastlogin-io/obligator"
	"github.com/takingnames/namedrop-go"
	//namedropdns "github.com/takingnames/namedrop-libdns"
	"github.com/libdns/libdns"
	"github.com/libdns/namedotcom"
	_ "github.com/mattn/go-sqlite3"
)

//go:embed templates
var fs embed.FS

func main() {
	domainArg := flag.String("domain", "", "Domain")
	tempDomainRootArg := flag.String("temp-domain-root", "", "Temporary domain root")
	adminIdArg := flag.String("admin-id", "", "Admin email address")
	providerIdArg := flag.String("dns-provider", "", "DNS provider ID")
	dnsUserId := flag.String("dns-user", "", "DNS user ID")
	dnsToken := flag.String("dns-token", "", "DNS token")
	flag.Parse()

	domain := *domainArg
	if domain == "" {
		exitOnError(errors.New("Domain required"))
	}

	adminId := *adminIdArg
	if adminId == "" {
		exitOnError(errors.New("Admin ID required"))
	}

	providerId := *providerIdArg
	if providerId != "name.com" {
		exitOnError(errors.New("Unsupported DNS provider"))
	}

	tempDomainRoot := *tempDomainRootArg
	if tempDomainRoot == "" {
		tempDomainRoot = "ip." + domain
	}

	db, err := sql.Open("sqlite3", "namedrop.sqlite")
	exitOnError(err)

	stmt := `
	PRAGMA foreign_keys = ON;
	PRAGMA synchronous = NORMAL;
	PRAGMA journal_mode = 'WAL';
	PRAGMA cache_size = -64000;
	`

	_, err = db.Exec(stmt)
	exitOnError(err)

	db.SetMaxOpenConns(1)

	provider, err := getDnsProvider(providerId, *dnsUserId, *dnsToken)
	exitOnError(err)

	tmpl, err := template.ParseFS(fs, "templates/*")
	exitOnError(err)

	store, err := decentauth.NewSqliteKvStore(&decentauth.SqliteKvOptions{
		TableName: "kv",
		Db:        db,
	})
	exitOnError(err)

	err = store.Set("temp_subdomain_zone", []byte(tempDomainRoot))
	exitOnError(err)

	ndServer := namedrop.NewServer(store, provider)

	authPrefix := "/auth"
	authHandler, err := decentauth.NewHandler(&decentauth.HandlerOptions{
		AdminId: adminId,
		Prefix:  authPrefix,
		KvStore: store,
	})
	exitOnError(err)

	mux := http.NewServeMux()

	idOrLogin := func(w http.ResponseWriter, r *http.Request) (id string, done bool) {

		session:= authHandler.GetSession(r)
		if session == nil || session.Id != adminId {
			authHandler.LoginRedirect(w, r)
			done = true
			return
		}

		id = session.Id
		return
	}

	//pendingTokens := make(map[string]*namedrop.TokenData)
	//mut := &sync.Mutex{}

	mux.Handle("/", ndServer)

	mux.Handle(authPrefix+"/", authHandler)
	mux.Handle(authPrefix, authHandler)

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		_, done := idOrLogin(w, r)
		if done {
			return
		}

		authReq, err := namedrop.ParseAuthRequest(r.Form)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		displayClientId := authReq.ClientId

		parsedClientId, err := url.Parse(authReq.ClientId)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		displayClientId = parsedClientId.Host

		hostParts := strings.Split(parsedClientId.Host, ":")

		if hostParts[0] == "localhost" {
			displayClientId = "An app on your device"
		}

		permDescriptions, err := namedrop.BuildPermDescriptions(authReq.RequestedPermissions)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		zones, err := provider.ListZones(context.Background())
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		data := struct {
			DisplayClientId  string
			Zones            []libdns.Zone
			PermDescriptions []string
			RawQuery         string
		}{
			DisplayClientId:  displayClientId,
			Zones:            zones,
			PermDescriptions: permDescriptions,
			RawQuery:         r.URL.RawQuery,
		}

		err = tmpl.ExecuteTemplate(w, "authorize.html", data)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	})

	mux.HandleFunc("/approved", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		id, done := idOrLogin(w, r)
		if done {
			return
		}

		authReqParamsStr := r.Form.Get("raw_query")
		params, err := url.ParseQuery(authReqParamsStr)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		authReq, err := namedrop.ParseAuthRequest(params)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		perms := []*namedrop.Permission{}
		scopes := []string{}

		for _, reqPerm := range authReq.RequestedPermissions {
			perm := &namedrop.Permission{
				Domain: r.Form.Get("requested_domain"),
				Host:   r.Form.Get("requested_host"),
				Scope:  reqPerm.Scope,
			}

			perms = append(perms, perm)
			scopes = append(scopes, reqPerm.Scope)
		}

		scopeParam := strings.Join(scopes, " ")

		createTokenData := &namedrop.TokenData{
			OwnerId:     id,
			Permissions: perms,
		}

		code, err := ndServer.CreateCode(createTokenData, authReqParamsStr)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		redirUrl := fmt.Sprintf("%s?state=%s&code=%s&scope=%s", authReq.RedirectUri, authReq.State, code, scopeParam)

		http.Redirect(w, r, redirUrl, 303)
	})

	fmt.Println("Running")
	err = http.ListenAndServe(":4004", mux)
	exitOnError(err)
}

//func createProvider(providerId, userId, token string) (libdns.Provider, error) {
//        provider := namedotcom.Provider{
//                Token: *dnsToken,
//                User: *dnsUserId,
//                Server: "https://api.name.com",
//        }
//
//        return provider, nil
//}

func getDnsProvider(provider, user, token string) (namedrop.DnsProvider, error) {
	switch provider {
	//case "takingnames":
	//	return &namedropdns.Provider{
	//		Token: token,
	//	}, nil
	case "name.com":
		return &namedotcom.Provider{
			Server: "https://api.name.com",
			Token:  token,
			User:   user,
		}, nil
		//case "route53":
		//	return &route53.Provider{
		//		WaitForPropagation: true,
		//		MaxWaitDur:         5 * time.Minute,
		//		// AccessKeyId and SecretAccessKey are grabbed from the environment
		//		//AccessKeyId:     user,
		//		//SecretAccessKey: token,
		//	}, nil
		//default:
		//	if !strings.HasPrefix(provider, "https://") {
		//		return nil, fmt.Errorf("Assuming NameDrop DNS provider, but %s is not a valid NameDrop server URI", provider)
		//	}
		//	// Assume provider is a NameDrop URI if nothing else matches
		//	return &namedropdns.Provider{
		//		ServerUri: provider,
		//		Token:     token,
		//	}, nil
	}

	return nil, errors.New("unknown error")
}

func exitOnError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func printJson(data interface{}) {
	d, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(d))
}
