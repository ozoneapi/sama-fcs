package server

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"time"

	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/discovery"

	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/labstack/echo"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"

	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/auth"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/model"
)

// ResponseType - Needs to be a interface{} slice, see the official test for an example
// https://github.com/go-ozzo/ozzo-validation/blob/master/in_test.go
type ResponseType = interface{}

// responseTypesSupported REQUIRED. JSON array containing a list of the OAuth 2.0 response_type values that this OP supports. Dynamic OpenID Providers MUST support the code, id_token, and the token id_token Response Type values
func responseTypesSupported() []ResponseType {
	return []ResponseType{
		"code",
		"code id_token",
		"id_token",
	}
}

type configHandlers struct {
	logger  *logrus.Entry
	journey Journey
}

// SupportedRequestSignAlg -
// Needs to be a interface{} slice, see the official test for an example
// https://github.com/go-ozzo/ozzo-validation/blob/master/in_test.go
type SupportedRequestSignAlg interface{}

// SupportedRequestSignAlgValues -
func SupportedRequestSignAlgValues() []interface{} {
	return []interface{}{"PS256", "RS256", "NONE"}
}

// SupportedAcrValues returns a slice of supported acr values to be used in the request object
// those are values that the Authorization Server is being requested to use for processing this Authentication Request
// https://openbanking.atlassian.net/wiki/spaces/DZ/pages/7046134/Open+Banking+Security+Profile+-+Implementer+s+Draft+v1.1.0
func SupportedAcrValues() []string {
	return []string{"urn:openbanking:psd2:sca", "urn:openbanking:psd2:ca"}
}

// TPPConfiguration -
type TPPConfiguration struct {
	SigningPrivate                string                               `json:"signing_private" validate:"not_empty"`
	SigningPublic                 string                               `json:"signing_public" validate:"not_empty"`
	TransportPrivate              string                               `json:"transport_private" validate:"not_empty"`
	TransportPublic               string                               `json:"transport_public" validate:"not_empty"`
	TPPSignatureKID               string                               `json:"tpp_signature_kid,omitempty"`
	TPPSignatureIssuer            string                               `json:"tpp_signature_issuer,omitempty"`
	TPPSignatureTAN               string                               `json:"tpp_signature_tan,omitempty"`
	ClientID                      string                               `json:"client_id" validate:"not_empty"`
	ClientSecret                  string                               `json:"client_secret" validate:"not_empty"`
	TokenEndpoint                 string                               `json:"token_endpoint" validate:"valid_url"`
	ResponseType                  string                               `json:"response_type" validate:"not_empty"`
	TokenEndpointAuthMethod       string                               `json:"token_endpoint_auth_method" validate:"not_empty"`
	AuthorizationEndpoint         string                               `json:"authorization_endpoint" validate:"valid_url"`
	ResourceBaseURL               string                               `json:"resource_base_url" validate:"valid_url"`
	XFAPIFinancialID              string                               `json:"x_fapi_financial_id" validate:"not_empty"`
	XFAPICustomerIPAddress        string                               `json:"x_fapi_customer_ip_address,omitempty"`
	RedirectURL                   string                               `json:"redirect_url" validate:"valid_url"`
	ResourceIDs                   model.ResourceIDs                    `json:"resource_ids" validate:"not_empty"`
	TransactionFromDate           string                               `json:"transaction_from_date" validate:"not_empty"`
	TransactionToDate             string                               `json:"transaction_to_date" validate:"not_empty"`
	RequestObjectSigningAlgorithm string                               `json:"request_object_signing_alg"`
	CurrencyOfTransfer            string                               `json:"currency_of_transfer"`
	AcrValuesSupported            []string                             `json:"acr_values_supported,omitempty"`
	ConditionalProperties         []discovery.ConditionalAPIProperties `json:"conditional_properties,omitempty"`
	LetterOfGuarantee             string                               `json:"letter_of_guarantee,omitempty"`
	Issuer                        string                               `json:"issuer" validate:"valid_url"`

	//CBPIIDebtorAccount            discovery.CBPIIDebtorAccount         `json:"cbpii_debtor_account"`
	// Should be taken from the well-known endpoint:
}

// Validate - used by https://github.com/go-ozzo/ozzo-validation to validate struct.
func Validate(c TPPConfiguration) error {
	values := responseTypesSupported()
	return validation.ValidateStruct(&c,
		validation.Field(&c.ResponseType, validation.Required, validation.In(values[:]...)),
		validation.Field(&c.CurrencyOfTransfer, validation.Match(regexp.MustCompile("^[A-Z]{3,3}$"))),
		validation.Field(&c.AcrValuesSupported, validation.By(acrValuesValidator)),
		//validation.Field(&c.CBPIIDebtorAccount, validation.Required),
	)
}

func futureDateTimeValidator(value interface{}) error {
	dateTimeStr, ok := value.(string)
	if !ok {
		return fmt.Errorf("futureDateTimeValidator: value must be a valid string")
	}
	parsedDateTime, err := time.Parse("2006-01-02T15:04:05-07:00", dateTimeStr)
	if err != nil {
		return errors.Wrapf(err, "futureDateTimeValidator: the date provided is not in a supported format, please use `2006-01-02T15:04:05-07:00`")
	}
	if time.Now().Unix() >= parsedDateTime.Unix() {
		return fmt.Errorf("futureDateTimeValidator: value must be a valid date in the future")
	}

	return nil
}

func acrValuesValidator(value interface{}) error {
	values, ok := value.([]string)
	if !ok {
		return nil
	}
	supportedAcrValues := SupportedAcrValues()
	if len(values) > len(supportedAcrValues) {
		return fmt.Errorf("acrValuesValidator: `acr_values_supported` cannot be more than %d", len(supportedAcrValues))
	}
	for _, v := range values {
		if !strSliceContains(supportedAcrValues, v) {
			return fmt.Errorf("acrValuesValidator: `acr_values_supported` invalid value provided: %s", v)
		}
	}

	return nil
}

func strSliceContains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}

	return false
}

func newConfigHandlers(journey Journey, logger *logrus.Entry) configHandlers {
	return configHandlers{
		journey: journey,
		logger:  logger.WithField("module", "configHandlers"),
	}
}

// GET /api/config/conditional-property
func (h configHandlers) configConditionalPropertyHandler(c echo.Context) error {
	conditionalProperties := h.journey.ConditionalProperties()
	filteredProps := make([]discovery.ConditionalAPIProperties, 0, len(conditionalProperties))
	for _, v := range conditionalProperties {
		if len(v.Endpoints) > 0 {
			filteredProps = append(filteredProps, v)
		}
	}
	return c.JSON(http.StatusOK, filteredProps)
}

// POST /api/config/global
func (h configHandlers) configGlobalPostHandler(c echo.Context) error {
	config := new(TPPConfiguration)
	if err := c.Bind(config); err != nil {
		return c.JSON(http.StatusBadRequest, NewErrorResponse(errors.Wrap(err, "error with Bind")))
	}

	if err := Validate(*config); err != nil {
		return c.JSON(http.StatusBadRequest, NewErrorResponse(err))
	}

	tppConfig, err := NewTPPConfig(config)
	if err != nil {
		return c.JSON(http.StatusBadRequest, NewErrorResponse(err))
	}

	// Use the transport keys for MATLS as some endpoints require this
	//resty.SetCertificates(tppConfig.certificateTransport.TLSCert()) // Needs attention for multitenant
	log.Warn("Need to set Resty Transport CERTIFICATES somewhere else")

	err = h.journey.SetConfig(tppConfig)
	if err != nil {
		return c.JSON(http.StatusBadRequest, NewErrorResponse(err))
	}

	return c.JSON(http.StatusCreated, config)
}

// NewTPPConfig -
func NewTPPConfig(config *TPPConfiguration) (TppConfig, error) {
	ok, message := validateConfig(config)
	if !ok {
		return TppConfig{}, errors.New(message)
	}

	certificateSigning, err := auth.NewPrivateKey(config.SigningPrivate)
	if err != nil {
		return TppConfig{}, errors.Wrap(err, "error with signing certificate")
	}

	certificateTransport, err := auth.NewCertificate(config.TransportPublic, config.TransportPrivate)
	if err != nil {
		return TppConfig{}, errors.Wrap(err, "error with transport certificate")
	}

	return TppConfig{
		certificateSigning:            certificateSigning,
		certificateTransport:          certificateTransport,
		signingPublic:                 config.SigningPublic,
		signingPrivate:                config.SigningPrivate,
		tppSignatureKID:               config.TPPSignatureKID,
		tppSignatureIssuer:            config.TPPSignatureIssuer,
		tppSignatureTAN:               config.TPPSignatureTAN,
		clientID:                      config.ClientID,
		clientSecret:                  config.ClientSecret,
		tokenEndpoint:                 config.TokenEndpoint,
		ResponseType:                  config.ResponseType,
		tokenEndpointAuthMethod:       config.TokenEndpointAuthMethod,
		authorizationEndpoint:         config.AuthorizationEndpoint,
		resourceBaseURL:               config.ResourceBaseURL,
		xXFAPIFinancialID:             config.XFAPIFinancialID,
		xXFAPICustomerIPAddress:       config.XFAPICustomerIPAddress,
		redirectURL:                   config.RedirectURL,
		resourceIDs:                   config.ResourceIDs,
		currencyOfTransfer:            config.CurrencyOfTransfer,
		transactionFromDate:           config.TransactionFromDate,
		transactionToDate:             config.TransactionToDate,
		requestObjectSigningAlgorithm: config.RequestObjectSigningAlgorithm,
		AcrValuesSupported:            config.AcrValuesSupported,
		conditionalProperties:         config.ConditionalProperties,
		//cbpiiDebtorAccount:            config.CBPIIDebtorAccount,
		issuer:            config.Issuer, // TBD: available from well-known ?
		letterOfGuarantee: config.LetterOfGuarantee,
	}, nil
}

func validateConfig(config *TPPConfiguration) (bool, string) {
	rules := parseRules(config)
	for _, rule := range rules {
		ok, message := rule.validateFunc(rule.property, rule.value)
		if !ok {
			return false, message
		}
	}
	return true, ""
}

type validationRule struct {
	property     string
	value        interface{}
	validateFunc validateFunc
}

type validateFunc func(key, value interface{}) (bool, string)

func notEmpty(key, value interface{}) (bool, string) {
	switch v := value.(type) {
	case string:
		if v == "" {
			return false, fmt.Sprintf("%s is empty", key)
		}
		return true, ""
	case model.ResourceIDs:

		emAccts := nilOrEmpty(v.AccountIDs)
		emStmts := nilOrEmpty(v.StatementIDs)

		if emAccts && emStmts {
			return false, fmt.Sprintf("%s is empty", key)
		}

		if emAccts {
			return false, fmt.Sprintf("%s.AccountIDs is empty", key)
		}
		// Some nested validation here, not great but need to think about validation for nested values
		for i, v := range v.AccountIDs {
			if v.AccountID == "" {
				return false, fmt.Sprintf("%s.AccountIDs contains an empty value at index %d", key, i)
			}
		}

		if emStmts {
			return false, fmt.Sprintf("%s.StatementIDs is empty", key)
		}
		// Some nested validation here, not great but need to think about validation for nested values
		for i, v := range v.StatementIDs {
			if v.StatementID == "" {
				return false, fmt.Sprintf("%s.StatementIDs contains an empty value at index %d", key, i)
			}
		}

		return true, ""
	}

	return false, fmt.Sprintf("%s type not found", key)
}

func validURL(key, value interface{}) (bool, string) {
	if _, err := url.Parse(value.(string)); err != nil {
		return false, fmt.Sprintf("invalid %s url: %s", key, err.Error())
	}
	return true, ""
}

func and(left, right validateFunc) validateFunc {
	return func(key, value interface{}) (bool, string) {
		ok, msg := left(key, value)
		if !ok {
			return false, msg
		}
		ok, msg = right(key, value)
		if !ok {
			return false, msg
		}
		return true, ""
	}
}

func rulesFunc() map[string]validateFunc {
	return map[string]validateFunc{
		"not_empty": notEmpty,
		"valid_url": and(notEmpty, validURL),
	}
}

func parseRules(config *TPPConfiguration) []validationRule {
	var rules []validationRule
	val := reflect.ValueOf(config).Elem()
	for i := 0; i < val.NumField(); i++ {
		valueField := val.Field(i)
		typeField := val.Type().Field(i)
		tag := typeField.Tag

		if tag.Get("validate") == "" {
			// no validate tag
			continue
		}

		validate, ok := rulesFunc()[tag.Get("validate")]
		if !ok {
			// no rule func found
			continue
		}

		rules = append(rules, validationRule{
			property:     tag.Get("json"),
			value:        valueField.Interface(),
			validateFunc: validate,
		})
	}
	return rules
}

func nilOrEmpty(v interface{}) bool {
	return v == nil || reflect.ValueOf(v).Len() == 0
}
