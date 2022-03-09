package namedrop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/caddyserver/certmagic"
	"golang.org/x/oauth2"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

type ClientDatabase interface {
	SetDNSRequest(string, DNSRequest)
	GetDNSRequest(string) (DNSRequest, error)
	DeleteDNSRequest(string)
}

type Client struct {
	db          ClientDatabase
	domain      string
	providerUri string
	tokens      map[string]TokenData
	mut         *sync.Mutex
}

type DNSRequest struct{}

func NewClient(db ClientDatabase, domain, providerUri string) *Client {

	client := &Client{
		db:          db,
		domain:      domain,
		providerUri: providerUri,
		tokens:      make(map[string]TokenData),
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

func (c *Client) buildOauthConfig() *oauth2.Config {
	oauthConf := &oauth2.Config{
		ClientID:     c.domain,
		ClientSecret: "fake-secret",
		Scopes:       []string{"subdomain"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("https://%s/authorize", c.providerUri),
			TokenURL: fmt.Sprintf("https://%s/token", c.providerUri),
		},
		RedirectURL: fmt.Sprintf("%s/namedrop/callback", c.domain),
	}

	return oauthConf
}

func (c *Client) DomainRequestLink() string {
	c.mut.Lock()
	defer c.mut.Unlock()

	oauthConf := c.buildOauthConfig()

	requestId, _ := genRandomKey()

	req := DNSRequest{}

	c.db.SetDNSRequest(requestId, req)

	tnLink := oauthConf.AuthCodeURL(requestId, oauth2.AccessTypeOffline)

	return tnLink
}

func (c *Client) GetToken(requestId, code string) (*TokenData, error) {
	// Ensure the request exists
	_, err := c.db.GetDNSRequest(requestId)
	if err != nil {
		return nil, err
	}

	c.db.DeleteDNSRequest(requestId)

	c.mut.Lock()
	oauthConf := c.buildOauthConfig()
	c.mut.Unlock()

	ctx := context.Background()
	tok, err := oauthConf.Exchange(ctx, code)
	if err != nil {
		fmt.Println(err.Error())
	}

	accessToken := tok.AccessToken

	c.mut.Lock()
	url := fmt.Sprintf("https://%s/token-data?access_token=%s", c.providerUri, accessToken)
	c.mut.Unlock()

	tokenResp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer tokenResp.Body.Close()
	bodyJson, err := io.ReadAll(tokenResp.Body)

	var namedropTokenData *TokenData
	err = json.Unmarshal(bodyJson, &namedropTokenData)
	if err != nil {
		return nil, err
	}

	if len(namedropTokenData.Scopes) < 1 {
		return nil, errors.New("No scopes returned")
	}

	c.mut.Lock()
	c.tokens[accessToken] = *namedropTokenData
	c.mut.Unlock()

	return namedropTokenData, nil
}

func (c *Client) CreateRecord(record Record) error {
	createRecordReqJson, err := json.Marshal(record)
	if err != nil {
		return err
	}

	c.mut.Lock()
	tokens := c.tokens
	c.mut.Unlock()

	accessToken := ""
	for token, tokenData := range tokens {
		if hasPerm(&record, tokenData.Scopes) {
			accessToken = token
			break
		}
	}

	if accessToken == "" {
		return errors.New("No appropriate token found")
	}

	c.mut.Lock()
	url := fmt.Sprintf("https://%s/records?access_token=%s", c.providerUri, accessToken)
	c.mut.Unlock()

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(createRecordReqJson))
	if err != nil {
		return err
	}

	httpClient := &http.Client{}

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return errors.New("Invalid status code. Body: " + string(body))
	}

	return nil
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

func (c *Client) GetPublicIpv4() (string, error) {
	return c.GetPublicIp("tcp4")
}

func (c *Client) GetPublicIpv6() (string, error) {
	return c.GetPublicIp("tcp6")
}

func (c *Client) GetPublicIp(network string) (string, error) {
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	var dialer net.Dialer

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, networkNotUsed, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	httpClient.Transport = transport

	resp, err := httpClient.Get(fmt.Sprintf("https://%s/my-ip", c.providerUri))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("Invalid HTTP code getting public IP")
	}

	ip := string(body)

	if ip == "" {
		return "", errors.New("No IP address returned")
	}

	return ip, nil
}

func CheckPublicAddress(host string, port int) error {

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	defer ln.Close()

	code, err := genRandomKey()
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				break
			}
			conn.Write([]byte(code))
			conn.Close()
		}
	}()

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	go func() {
		time.Sleep(time.Second)
		conn.Close()
	}()

	data, err := io.ReadAll(conn)
	if err != nil {
		return errors.New(fmt.Sprintf("Error connecting to public address %s. Probably timed out", addr))
	}

	retCode := string(data)

	if retCode != code {
		return errors.New("Mismatched codes")
	}

	return nil
}
