package services

import(
	"time"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"context"
	"strings"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
)

type OAuth2User struct {
	Id            string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
}

type OAuth2Token struct {
	AccessToken   string `json:"access_token"`
}

type OAuth2Provider interface {
	GetURL(state string) string
	GetUserInfo(code string) (OAuth2User, error)
}

// Google OAuth

type GoogleProvider struct {
	oAuthConfig *oauth2.Config
}

func NewGoogleProvider(redirectDomain string, tenantID string, clientID string, clientSecret string) *GoogleProvider {
	p := GoogleProvider{}
	p.oAuthConfig = &oauth2.Config{
		RedirectURL:  fmt.Sprintf("%s/auth/google/callback", redirectDomain),
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
	p.oAuthConfig.Endpoint = google.Endpoint
	p.oAuthConfig.Scopes = []string{"https://www.googleapis.com/auth/userinfo.email"}
	return &p
}

func (p *GoogleProvider) GetURL(state string) string {
	url :=  p.oAuthConfig.AuthCodeURL(state)
	// `select_account` forces displaying the Google account selection step, in case the user has multiple
	//  accounts registered on their device.
	url += "&prompt=select_account"
	println(fmt.Sprintf("URL = %s", url))
	return url
}

func (p *GoogleProvider) GetUserInfo(code string) (OAuth2User, error) {
	const googleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="
	var user OAuth2User

	token, err := p.oAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		return user, fmt.Errorf("OAuth2Controller: exchange code is wrong: %s", err.Error())
	}
	response, err := http.Get(googleUserInfoURL + token.AccessToken)
	if err != nil {
		return user, fmt.Errorf("OAuth2Controller: failed to get user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return user, fmt.Errorf("OAuth2Controller: failed to read response: %s", err.Error())
	}

	err = json.Unmarshal(contents, &user)
	return user, err
}

// Microsoft/Azure OAuth

type MicrosoftProvider struct {
	oAuthConfig *oauth2.Config
}

func NewMicrosoftProvider(redirectDomain string, tenantID string, clientID string, clientSecret string) *MicrosoftProvider {
	p := MicrosoftProvider{}
	p.oAuthConfig = &oauth2.Config{
		RedirectURL:  fmt.Sprintf("%s/auth/azure/callback", redirectDomain),
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
	p.oAuthConfig.Endpoint = microsoft.AzureADEndpoint(tenantID)
	p.oAuthConfig.Scopes = []string{"openid", "email"}
	return &p
}

func (p *MicrosoftProvider) GetURL(state string) string {
	return p.oAuthConfig.AuthCodeURL(state)
}

func (p *MicrosoftProvider) GetUserInfo(code string) (OAuth2User, error) {
	const azureUserInfoURL = "https://graph.microsoft.com/oidc/userinfo"
	var user OAuth2User

	token, err := p.oAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		return user, fmt.Errorf("OAuth2Controller: exchange code is wrong: %s", err.Error())
	}
	client := http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", azureUserInfoURL, nil)
	req.Header.Set("authorization", "Bearer "+token.AccessToken)
	response, err := client.Do(req)
	if err != nil {
		return user, fmt.Errorf("OAuth2Controller: failed to get user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return user, fmt.Errorf("OAuth2Controller: failed to read response: %s", err.Error())
	}

	err = json.Unmarshal(contents, &user)
	return user, err
}

// Generic OAuth

type GenericProvider struct {
	oAuthConfig  *oauth2.Config
	authorizeUrl string
	tokenUrl     string
	userInfoUrl  string
}

func NewGenericProvider(redirectDomain string, authorizeUrl string, tokenUrl url, userInfoUrl string, clientID string, clientSecret string) *MicrosoftProvider {
	p := GenericProvider{}
	p.oAuthConfig = &oauth2.Config{
		RedirectURL:  fmt.Sprintf("%s/auth/generic/callback", redirectDomain),
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
	p.authorizeUrl = authorizeUrl
	p.tokenUrl = tokenUrl
	p.userInfoUrl = userInfoUrl
	return &p
}

func (p *GenericProvider) GetURL(state string) string {
	return fmt.Sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+email&state=%s", authorizeUrl, p.oAuthConfig.ClientID, url.QueryEscape(p.oAuthConfig.RedirectURL), state),
}

func (p *MicrosoftProvider) GetUserInfo(code string) (OAuth2User, error) {
	var token OAuth2Token
	var user OAuth2User

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", url.QueryEscape(p.oAuthConfig.RedirectURL))
	data.Set("code", code)
	data.Set("client_id", p.oAuthConfig.ClientID)
	data.Set("client_secret", p.oAuthConfig.ClientSecret)
	
	client := http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodPost, p.tokenUrl, strings.NewReader(data.Encode())) // URL-encoded payload
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(req)
	if err != nil {
		return user, fmt.Errorf("OAuth2Controller: failed to get token: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return user, fmt.Errorf("OAuth2Controller: failed to read token response: %s", err.Error())
	}
	
	err = json.Unmarshal(contents, &token)
	
	client = http.Client{Timeout: 10 * time.Second}
	req, err = http.NewRequest("GET", p.userInfoUrl, nil)
	req.Header.Set("authorization", "Bearer " + token.AccessToken)
	response, err = client.Do(req)
	if err != nil {
		return user, fmt.Errorf("OAuth2Controller: failed to get user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return user, fmt.Errorf("OAuth2Controller: failed to read userinfo response: %s", err.Error())
	}

	err = json.Unmarshal(contents, &user)
	return user, err
}