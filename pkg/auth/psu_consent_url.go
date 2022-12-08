package auth

import (
	"fmt"
	"net/url"

	"github.com/golang-jwt/jwt"
)

// PSUConsentClaims -
type PSUConsentClaims struct {
	AuthorizationEndpoint string
	Aud                   string // Audience
	Iss                   string // ClientID
	ResponseType          string // "code id_token"
	Scope                 string // "openid accounts"
	RedirectURI           string
	ConsentID             string
	State                 string // {test_id}
}

// PSUURLGenerate generates a PSU Consent URL based on claims
func PSUURLGenerate(claims PSUConsentClaims) (*url.URL, error) {
	token, err := createAlgNoneJWT(claims)
	if err != nil {
		return nil, fmt.Errorf("generating psu consent URL: %w", err)
	}

	consentURL, err := url.Parse(claims.AuthorizationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("generating psu consent URL: %w", err)
	}

	consentURLQuery := consentURL.Query()
	consentURLQuery.Set("client_id", claims.Iss)
	consentURLQuery.Set("response_type", claims.ResponseType)
	consentURLQuery.Set("scope", claims.Scope)
	consentURLQuery.Set("request", token)
	consentURLQuery.Set("state", claims.State)
	consentURL.RawQuery = consentURLQuery.Encode()

	return consentURL, nil
}

func createAlgNoneJWT(claims PSUConsentClaims) (string, error) {
	alg := jwt.SigningMethodNone
	if alg == nil {
		return "", fmt.Errorf("no signing method: %v", alg)
	}

	token := &jwt.Token{
		Header: map[string]interface{}{
			"alg": alg.Alg(),
		},
		Claims: makeOpenBankingJWTClaims(claims),
		Method: alg,
	}

	tokenString, err := token.SigningString()
	if err != nil {
		return "", err
	}

	// alg none might cause problems for some JWT parses so we add the "."
	// to terminate the jwt
	tokenString += "."

	return tokenString, nil
}

type openBankingClaims struct {
	IDToken idToken `json:"id_token,omitempty"`
}

type idToken struct {
	IntentID intentID `json:"openbanking_intent_id,omitempty"`
}

type intentID struct {
	Essential bool   `json:"essential"`
	Value     string `json:"value"`
}

func makeOpenBankingJWTClaims(claims PSUConsentClaims) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":          claims.Iss,
		"scope":        claims.Scope,
		"aud":          claims.Aud,
		"redirect_uri": claims.RedirectURI,
		"claims": openBankingClaims{
			IDToken: idToken{
				IntentID: intentID{
					Essential: true,
					Value:     claims.ConsentID,
				},
			},
		},
	}
}
