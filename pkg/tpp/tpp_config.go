package tpp

import (
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/discovery"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/model"
)

// Configuration -
type Configuration struct {
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
	//CBPIIDebtorAccount            discovery.CBPIIDebtorAccount         `json:"cbpii_debtor_account"`
	// Should be taken from the well-known endpoint:
	Issuer string `json:"issuer" validate:"valid_url"`
}
