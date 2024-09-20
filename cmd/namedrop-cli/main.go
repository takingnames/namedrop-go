package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"

	oauth "github.com/anderspitman/little-oauth2-go"
	"github.com/caddyserver/certmagic"
	"github.com/mdp/qrterminal/v3"
	"github.com/takingnames/namedrop-go"
)

func main() {

	apiUri := "takingnames.io/namedrop"
	serverUri := fmt.Sprintf("https://%s", apiUri)

	ips, err := namedrop.GetPublicIps(apiUri)
	checkErr(err)

	httpsPort := 443

	err = namedrop.CheckPublicAddress(ips.IPv4, httpsPort)
	checkErr(err)

	err = namedrop.CheckPublicAddress(ips.IPv6, httpsPort)
	checkErr(err)

	bootstrapDomain, err := namedrop.GetIpDomain(apiUri)
	checkErr(err)

	ctx := context.Background()
	err = certmagic.ManageAsync(ctx, []string{bootstrapDomain})
	checkErr(err)

	scopes := []string{namedrop.ScopeHosts}

	ar := &oauth.AuthRequest{
		RedirectUri: fmt.Sprintf("https://%s/callback", bootstrapDomain),
		Scopes:      scopes,
	}

	authUri := fmt.Sprintf("https://%s/authorize", apiUri)
	flowState, err := oauth.StartAuthCodeFlow(authUri, ar)
	checkErr(err)

	qrterminal.GenerateHalfBlock(flowState.AuthUri, qrterminal.L, os.Stdout)

	fmt.Println("\nTo continue, scan the QR code above, or use the URL below:\n")

	fmt.Println(flowState.AuthUri)

	certConfig := certmagic.NewDefault()

	tlsConfig := &tls.Config{
		GetCertificate: certConfig.GetCertificate,
		//NextProtos:     []string{"h2", "acme-tls/1"},
	}

	var code string
	var state string
	var callbackErr error

	server := http.Server{
		Addr:      fmt.Sprintf(":%d", httpsPort),
		TLSConfig: tlsConfig,
	}

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code = r.URL.Query().Get("code")
		state = r.URL.Query().Get("state")

		tokenUri := fmt.Sprintf("https://%s/token", apiUri)
		resBytes, callbackErr := oauth.CompleteAuthCodeFlow(tokenUri, code, state, flowState)
		if callbackErr != nil {
			w.WriteHeader(500)
			io.WriteString(w, callbackErr.Error())
			return
		}

		var tokenRes *namedrop.TokenResponse

		callbackErr = json.Unmarshal(resBytes, &tokenRes)
		if callbackErr != nil {
			w.WriteHeader(500)
			io.WriteString(w, callbackErr.Error())
			return
		}

		perm := tokenRes.Permissions[0]

		recordsReq := &namedrop.RecordsRequest{
			Token: tokenRes.AccessToken,
			Records: []*namedrop.Record{
				&namedrop.Record{
					Domain: perm.Domain,
					Host:   perm.Host,
					Type:   "A",
					Value:  ips.IPv4,
				},
				&namedrop.Record{
					Domain: perm.Domain,
					Host:   perm.Host,
					Type:   "AAAA",
					Value:  ips.IPv6,
				},
				&namedrop.Record{
					Domain: perm.Domain,
					Host:   "*." + perm.Host,
					Type:   "A",
					Value:  ips.IPv4,
				},
				&namedrop.Record{
					Domain: perm.Domain,
					Host:   "*." + perm.Host,
					Type:   "AAAA",
					Value:  ips.IPv6,
				},
			},
		}

		callbackErr = namedrop.SetRecords(serverUri, recordsReq)
		if callbackErr != nil {
			w.WriteHeader(500)
			io.WriteString(w, callbackErr.Error())
			return
		}

		html := `
                  <!doctype html>
                  <html>
                    <head>
                      <meta charset="utf-8">
                      <meta name="viewport" content="width=device-width, initial-scale=1" />
                      <style>

                        body {
                          font-family: Arial;
                          font-size: 28px;
                          display: flex;
                          justify-content: center;
                          margin: 0px;
                          line-height: 1.5;
                        }

                        .content {
                          margin-top: 30vh;
                          max-width: 640px;
                          width: 100%;
                          padding: 5px;
                        }

                      </style>
                    </head>
                    <body>
                      <div class='content'>
                        <p>
                          <strong>{{.Fqdn}}</strong> has been set up successfully. Feel free to close this tab,
                          or click <a href='https://{{.Fqdn}}'>this link</a> to navigate to https://{{.Fqdn}}.
                        </p>
                      </div>
                    </body>
                  </html>
                `

		tmpl, callbackErr := template.New("html").Parse(html)
		if callbackErr != nil {
			w.WriteHeader(500)
			io.WriteString(w, callbackErr.Error())
			return
		}

		fqdn := perm.Domain
		if perm.Host != "" {
			fqdn = fmt.Sprintf("%s.%s", perm.Host, perm.Domain)
		}

		data := struct {
			Fqdn string
		}{
			Fqdn: fqdn,
		}

		callbackErr = tmpl.Execute(w, data)
		if callbackErr != nil {
			w.WriteHeader(500)
			io.WriteString(w, callbackErr.Error())
			return
		}

		// TODO: race condition?
		go func() {
			callbackErr = server.Shutdown(context.Background())
		}()
	})

	checkErr(callbackErr)

	server.ListenAndServeTLS("", "")
}

func checkErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func printJson(data interface{}) {
	d, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(d))
}
