package auth

import (
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

const hmacSampleSecret = "theraininspainfallsmainlyontheplain"

// JwtParts -
type JwtParts struct {
	header    string
	payload   string
	signature string
}

// JSONfromJWT -
// Returns the data part of a jwt as a json string
func JSONfromJWT(rawBody string) (string, error) {
	jwt, err := splitToken(rawBody)

	_, _ = jwt, err

	return "", nil
}

// splits token into 3 parts
// header, payload, signature
func splitToken(token string) (JwtParts, error) {
	jwtParts := JwtParts{}
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return jwtParts, errors.New("Signature Token does not have 3 segments: " + token)
	}

	jwtParts.header = segments[0]
	jwtParts.payload = segments[1]
	jwtParts.signature = segments[2]

	return jwtParts, nil
}

// GetSignatureToken314Plus returns the Token with correct headers for v3.1.4 and above of the R/W Apis
func NewKSAJwt(kid, issuer, trustAnchor string, alg jwt.SigningMethod) jwt.Token {
	token := jwt.Token{
		Header: map[string]interface{}{
			"typ":                           "JOSE",
			"kid":                           kid,
			"cty":                           "application/json",
			"http://openbanking.org.uk/iat": time.Now().Unix(),
			"http://openbanking.org.uk/iss": issuer,      //ASPSP ORGID or TTP ORGID/SSAID
			"http://openbanking.org.uk/tan": trustAnchor, //Trust anchor
			"alg":                           alg.Alg(),
			"crit": []string{
				"http://openbanking.org.uk/iat",
				"http://openbanking.org.uk/iss",
				"http://openbanking.org.uk/tan",
			},
		},
		Method: alg,
	}
	return token
}

// CreateSignedJWT ...
func CreateSignedJWT(signingAlg, body string, cliams map[string]string, ctx ContextInterface) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"foo": "bar",
		"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	})
	tokenString, err := token.SignedString([]byte(hmacSampleSecret))
	if err != nil {
		return "", errors.Wrap(err, "CreateSignedJWT failed ")
	}
	return tokenString, nil
}
