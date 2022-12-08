package auth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/client"
	"github.com/sirupsen/logrus"
)

// OpenIDConfiguration - The OpenID Connect discovery document retrieved by calling /.well-known/openid-configuration.
// https://openid.net/specs/openid-connect-discovery-1_0.html
type OpenIDConfiguration struct {
	TokenEndpoint                          string   `json:"token_endpoint,omitempty"`
	TokenEndpointAuthMethodsSupported      []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`
	AuthorizationEndpoint                  string   `json:"authorization_endpoint,omitempty"`
	Issuer                                 string   `json:"issuer,omitempty"`
	ResponseTypesSupported                 []string `json:"response_types_supported,omitempty"`
	AcrValuesSupported                     []string `json:"acr_values_supported,omitempty"`
	JwksURI                                string   `json:"jwks_uri,omitempty"`
	PARendpoint                            string   `json:"pushed_authorization_request_endpoint"`
}

var jwksURI = ""

// GetJWKSUri -
func GetJWKSUri() string {
	return jwksURI
}

// CachedOpenIDConfigGetter - pretty pointless ...
type CachedOpenIDConfigGetter struct {
	client *http.Client
}

// NewOpenIDConfigGetter --
func NewOpenIDConfigGetter() *CachedOpenIDConfigGetter {
	return &CachedOpenIDConfigGetter{
		client: client.NewHTTPClient(client.DefaultTimeout),
	}
}

// Get -
func (g CachedOpenIDConfigGetter) Get(url string) (OpenIDConfiguration, error) {
	config := OpenIDConfiguration{}

	resp, err := g.client.Get(url)
	if err != nil {
		return OpenIDConfiguration{}, fmt.Errorf("Failed to GET OpenIDConfiguration: url=%+v : %w", url, err)
	}

	if resp.StatusCode != http.StatusOK {
		responseBody, err := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		if err != nil {
			return OpenIDConfiguration{}, fmt.Errorf("error reading error response from GET OpenIDConfiguration: %w", err)
		}

		return OpenIDConfiguration{}, fmt.Errorf(
			"failed to GET OpenIDConfiguration config: url=%+v, StatusCode=%+v, body=%+v",
			url,
			resp.StatusCode,
			string(responseBody),
		)
	}

	defer resp.Body.Close()
	config = OpenIDConfiguration{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return config, fmt.Errorf("Invalid OpenIDConfiguration: url=%+v: %w", url, err)
	}

	logrus.Tracef("JWKS Uri = %s", config.JwksURI)
	jwksURI = config.JwksURI
	return config, nil
}
