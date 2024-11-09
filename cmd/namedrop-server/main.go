package main

import (
	//"time"
	//"sync"
	"context"
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

	"github.com/lastlogin-io/obligator"
	"github.com/takingnames/namedrop-go"
	//namedropdns "github.com/takingnames/namedrop-libdns"
	"github.com/libdns/libdns"
	"github.com/libdns/namedotcom"
	//"github.com/philippgille/gokv/syncmap"
	filestore "github.com/philippgille/gokv/file"
)

//go:embed templates
var fs embed.FS

type DnsProvider interface {
	libdns.ZoneLister
}

func main() {
	domainArg := flag.String("domain", "", "Domain")
	adminIdArg := flag.String("admin", "", "Admin email address")
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

	provider, err := getDnsProvider(providerId, *dnsUserId, *dnsToken)
	exitOnError(err)

	tmpl, err := template.ParseFS(fs, "templates/*")
	exitOnError(err)

	store, err := filestore.NewStore(filestore.Options{
		Directory: "./db",
	})
	exitOnError(err)

	defer store.Close()

	ndServer := namedrop.NewServer(store)

	mux := http.NewServeMux()

	authUri := fmt.Sprintf("https://login.%s", domain)

	idOrLogin := func(w http.ResponseWriter, r *http.Request) (id string, done bool) {
		id = r.Header.Get("Remote-Id")
		if id != adminId {
			returnUri := fmt.Sprintf("https://%s%s", r.Host, r.RequestURI)
			uri := fmt.Sprintf("%s/login?return_uri=%s", authUri, url.QueryEscape(returnUri))
			http.Redirect(w, r, uri, 302)
			done = true
			return
		}

		return
	}

	//pendingTokens := make(map[string]*namedrop.TokenData)
	//mut := &sync.Mutex{}

	mux.Handle("/token", ndServer)

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

		permDescriptions := []string{}

		for _, perm := range authReq.RequestedPermissions {
			var description string

			switch perm.Scope {
			case namedrop.ScopeHosts:
				description = "Change the servers pointed to by "
			case namedrop.ScopeMail:
				description = "Change mail servers and settings for "
			case namedrop.ScopeAcme:
				description = "Obtain security (TLS) certificates for "
			case namedrop.ScopeAtprotoHandle:
				description = "Set a custom Bluesky/atproto handle for "
			default:
				http.Error(w, "Unknown scope "+perm.Scope, 400)
				return
			}

			permDescriptions = append(permDescriptions, description)
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

	dbPrefix := "auth_"

	ogConfig := obligator.ServerConfig{
		DbPrefix:               dbPrefix,
		DisplayName:            "NameDrop Server",
		Port:                   4004,
		Prefix:                 "namedrop_",
		ForwardAuthPassthrough: true,
		Public:                 true,
		Domains: []string{
			domain,
		},
		//LogoPng:        logoPngBytes,
		DisableQrLogin: true,
		OAuth2Providers: []*obligator.OAuth2Provider{
			&obligator.OAuth2Provider{
				ID:            "lastlogin",
				Name:          "LastLogin",
				URI:           "https://lastlogin.net",
				ClientID:      authUri,
				OpenIDConnect: true,
			},
		},
	}
	ogServer := obligator.NewServer(ogConfig)

	ogServer.ProxyMux(domain, mux)

	ogServer.Start()
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

func getDnsProvider(provider, user, token string) (DnsProvider, error) {
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
