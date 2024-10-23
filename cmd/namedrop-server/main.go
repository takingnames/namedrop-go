package main

import (
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

	"github.com/lastlogin-io/obligator"
	"github.com/takingnames/namedrop-go"
	//namedropdns "github.com/takingnames/namedrop-libdns"
	"github.com/libdns/libdns"
	"github.com/libdns/namedotcom"
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

	mux := http.NewServeMux()

	authUri := fmt.Sprintf("https://login.%s", domain)

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		id := r.Header.Get("Remote-Id")
		if id != adminId {
			returnUri := fmt.Sprintf("https://%s%s", r.Host, r.RequestURI)
			uri := fmt.Sprintf("%s/login?return_uri=%s", authUri, url.QueryEscape(returnUri))
			http.Redirect(w, r, uri, 302)
			return
		}

		authReq, err := namedrop.ParseAuthRequest(r.Form)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		printJson(authReq)

		zones, err := provider.ListZones(context.Background())
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		printJson(zones)

		data := struct {
		}{}

		err = tmpl.ExecuteTemplate(w, "authorize.html", data)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
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
				URI:           "https://lastlogin.io",
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
