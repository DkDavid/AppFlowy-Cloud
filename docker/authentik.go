package provider

import (
	"context"
	"strconv"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

// Gitlab

const defaultAuthentikAuthBase = "authentik.com"

type authentikProvider struct {
	*oauth2.Config
	Host string
}

type authentikUser struct {
	Email       string `json:"email"`
	Name        string `json:"name"`
	AvatarURL   string `json:"avatar_url"`
	ConfirmedAt string `json:"confirmed_at"`
	ID          int    `json:"id"`
}

type authentikUserEmail struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
}

// NewauthentikProvider creates a Gitlab account provider.
func NewAuthentikProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	oauthScopes := []string{
		"read_user",
		"user",
		"email",
		"offline_access",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	host := chooseHost(ext.URL, defaultAuthentikAuthBase)
	return &authentikProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  host + "/application/o/authorize/",
				TokenURL: host + "/application/o/token/",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		Host: host,
	}, nil
}

func (g authentikProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(context.Background(), code)
}

func (g authentikProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u authentikUser

	if err := makeRequest(ctx, tok, g.Config, g.Host+"/application/o/userinfo/", &u); err != nil {
		return nil, err
	}

	data := &UserProvidedData{}

	if u.Email != "" {
		verified := u.ConfirmedAt != ""
		data.Emails = append(data.Emails, Email{Email: u.Email, Verified: verified, Primary: true})
	}

	data.Metadata = &Claims{
		Issuer:  g.Host,
		Subject: strconv.Itoa(u.ID),
		Name:    u.Name,
		Picture: u.AvatarURL,

		// To be deprecated
		AvatarURL:  u.AvatarURL,
		FullName:   u.Name,
		ProviderId: strconv.Itoa(u.ID),
	}

	return data, nil
}
