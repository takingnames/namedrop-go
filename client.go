package namedrop

import (
	"context"
	"errors"
	"fmt"
	"github.com/caddyserver/certmagic"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"sync"
)

type ClientDatabase interface {
	SetDNSRequest(string, DNSRequest)
}

type Client struct {
	db          ClientDatabase
	domain      string
	providerUri string
	mut         *sync.Mutex
}

type DNSRequest struct {
	IsAdminDomain bool `json:"is_admin_domain"`
}

func NewClient(db ClientDatabase, domain, providerUri string) *Client {

	client := &Client{
		db:          db,
		domain:      domain,
		providerUri: providerUri,
		mut:         &sync.Mutex{},
	}

	return client
}

func (c *Client) SetDomain(domain string) {
	c.mut.Lock()
	defer c.mut.Unlock()

	c.domain = domain
}

func (c *Client) BootstrapLink() (string, error) {
	bootstrapDomain, err := c.GetIpDomain()
	if err != nil {
		return "", err
	}

	ctx := context.Background()
	err = certmagic.ManageSync(ctx, []string{bootstrapDomain})
	if err != nil {
		return "", err
	}

	c.SetDomain(bootstrapDomain)
	return c.DomainRequestLink(), nil
}

func (c *Client) DomainRequestLink() string {
	c.mut.Lock()
	defer c.mut.Unlock()

	oauthConf := &oauth2.Config{
		ClientID:     c.domain,
		ClientSecret: "fake-secret",
		Scopes:       []string{"subdomain"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("https://%s/authorize", c.providerUri),
			TokenURL: fmt.Sprintf("https://%s/token", c.providerUri),
		},
		RedirectURL: fmt.Sprintf("%s/namedrop/auth-success", c.domain),
	}

	requestId, _ := genRandomKey()

	req := DNSRequest{
		IsAdminDomain: true,
	}

	c.db.SetDNSRequest(requestId, req)

	tnLink := oauthConf.AuthCodeURL(requestId, oauth2.AccessTypeOffline)

	return tnLink
}

func (c *Client) GetIpDomain() (string, error) {

	url := fmt.Sprintf("https://%s/ip-domain", c.providerUri)
	resp, err := http.Post(url, "", nil)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return "", errors.New("IP domain request failed")
	}

	return string(body), nil
}
