package server

import (
	"fmt"

	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/auth"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/model"
	"github.com/sirupsen/logrus"
)

// Context Variables
const (
	CtxTPPSignatureKID                     = "tpp_signature_kid"
	CtxTPPSignatureIssuer                  = "tpp_signature_issuer"
	CtxTPPSignatureTAN                     = "tpp_signature_tan"
	CtxConstClientID                       = "client_id"
	CtxConstClientSecret                   = "client_secret"
	CtxConstTokenEndpoint                  = "token_endpoint"
	CtxResponseType                        = "responseType"
	CtxConstTokenEndpointAuthMethod        = "token_endpoint_auth_method"
	CtxConstFapiFinancialID                = "x-fapi-financial-id"
	CtxConstFapiCustomerIPAddress          = "x-fapi-customer-ip-address"
	CtxConstRedirectURL                    = "redirect_url"
	CtxConstAuthorisationEndpoint          = "authorisation_endpoint"
	CtxConstBasicAuthentication            = "basic_authentication"
	CtxConstResourceBaseURL                = "resource_server"
	CtxConstIssuer                         = "issuer"
	CtxAPIVersion                          = "api-version"
	CtxConsentedAccountID                  = "consentedAccountId"
	CtxStatementID                         = "statementId"
	CtxInternationalCreditorSchema         = "internationalCreditorScheme"
	CtxInternationalCreditorIdentification = "internationalCreditorIdentification"
	CtxInternationalCreditorName           = "internationalCreditorName"
	CtxCBPIIDebtorAccountName              = "cbpiiDebtorAccountName"
	CtxCBPIIDebtorAccountSchemeName        = "cbpiiDebtorAccountSchemeName"
	CtxCBPIIDebtorAccountIdentification    = "cbpiiDebtorAccountIdentification"
	CtxCreditorSchema                      = "creditorScheme"
	CtxCreditorIdentification              = "creditorIdentification"
	CtxCreditorName                        = "creditorName"
	CtxInstructedAmountCurrency            = "instructedAmountCurrency"
	CtxInstructedAmountValue               = "instructedAmountValue"
	CtxPaymentFrequency                    = "payment_frequency" // CtxPaymentFrequency - for example `EvryDay`.
	CtxFirstPaymentDateTime                = "firstPaymentDateTime"
	CtxRequestedExecutionDateTime          = "requestedExecutionDateTime"
	CtxCurrencyOfTransfer                  = "currencyOfTransfer"
	CtxTransactionFromDate                 = "transactionFromDate"
	CtxTransactionToDate                   = "transactionToDate"
	CtxRequestObjectSigningAlg             = "requestObjectSigningAlg"
	CtxSigningPrivate                      = "signingPrivate"
	CtxSigningPublic                       = "signingPublic"
	CtxPhase                               = "phase"
	CtxDynamicResourceIDs                  = "dynamicResourceIDs"
	CtxAcrValuesSupported                  = "acrValuesSupported"
	CtxUserAgentString                     = "userAgentString"
	CtxLetterOfGuarantee                   = "letterOfGuarantee"
)

// PutParametersToJourneyContext populates a JourneyContext with values from the config screen
func PutParametersToJourneyContext(config TppConfig, context model.Context) error {
	config.apiVersion = "v3.1"

	context.PutString(CtxConstClientID, config.clientID)
	context.PutString(CtxConstClientSecret, config.clientSecret)
	context.PutString(CtxTPPSignatureKID, config.tppSignatureKID)
	context.PutString(CtxTPPSignatureIssuer, config.tppSignatureIssuer)
	context.PutString(CtxTPPSignatureTAN, config.tppSignatureTAN)
	context.PutString(CtxConstTokenEndpoint, config.tokenEndpoint)
	context.PutString(CtxResponseType, config.ResponseType)
	context.PutString(CtxConstTokenEndpointAuthMethod, config.tokenEndpointAuthMethod)
	context.PutString(CtxConstFapiFinancialID, config.xXFAPIFinancialID)
	context.PutString(CtxConstFapiCustomerIPAddress, config.xXFAPICustomerIPAddress)
	context.PutString(CtxConstRedirectURL, config.redirectURL)
	context.PutString(CtxConstAuthorisationEndpoint, config.authorizationEndpoint)
	context.PutString(CtxConstResourceBaseURL, config.resourceBaseURL)
	context.PutString(CtxAPIVersion, config.apiVersion)
	context.PutString(CtxConsentedAccountID, config.resourceIDs.AccountIDs[0].AccountID)
	context.PutString(CtxStatementID, config.resourceIDs.StatementIDs[0].StatementID)
	context.PutString(CtxInternationalCreditorSchema, config.internationalCreditorAccount.SchemeName)
	context.PutString(CtxInternationalCreditorIdentification, config.internationalCreditorAccount.Identification)
	context.PutString(CtxInternationalCreditorName, config.internationalCreditorAccount.Name)
	context.PutString(CtxCreditorSchema, config.creditorAccount.SchemeName)
	context.PutString(CtxCreditorIdentification, config.creditorAccount.Identification)
	context.PutString(CtxCreditorName, config.creditorAccount.Name)
	// context.PutString(CtxCBPIIDebtorAccountName, config.cbpiiDebtorAccount.Name)
	// context.PutString(CtxCBPIIDebtorAccountSchemeName, config.cbpiiDebtorAccount.SchemeName)
	// context.PutString(CtxCBPIIDebtorAccountIdentification, config.cbpiiDebtorAccount.Identification)
	context.PutString(CtxInstructedAmountCurrency, config.instructedAmount.Currency)
	context.PutString(CtxInstructedAmountValue, config.instructedAmount.Value)
	context.PutString(CtxPaymentFrequency, string(config.paymentFrequency))
	context.PutString(CtxFirstPaymentDateTime, config.firstPaymentDateTime)
	context.PutString(CtxRequestedExecutionDateTime, config.requestedExecutionDateTime)
	context.PutString(CtxCurrencyOfTransfer, config.currencyOfTransfer)
	context.PutString(CtxRequestObjectSigningAlg, config.requestObjectSigningAlgorithm)
	context.PutString(CtxSigningPrivate, config.signingPrivate)
	context.PutString(CtxSigningPublic, config.signingPublic)
	context.PutString(CtxTransactionFromDate, config.transactionFromDate)
	context.PutString(CtxTransactionToDate, config.transactionToDate)
	context.Put(CtxDynamicResourceIDs, config.useDynamicResourceID)
	context.PutStringSlice(CtxAcrValuesSupported, config.AcrValuesSupported)
	context.PutString(CtxLetterOfGuarantee, config.letterOfGuarantee)

	basicauth, err := auth.CalculateClientSecretBasicToken(config.clientID, config.clientSecret)
	if err != nil {
		return err
	}
	context.PutString(CtxConstBasicAuthentication, basicauth)
	context.PutString(CtxConstIssuer, config.issuer)
	context.PutString(CtxPhase, "unknown")

	if config.useDynamicResourceID {
		context.Delete(CtxConsentedAccountID)
		context.Delete(CtxStatementID)
	}

	_, ou, cn, err := config.certificateTransport.DN()
	if err == nil && cn != "" && ou != "" {
		//resty.SetHeader("User-Agent", "OzoneFCS/"+version.NewGitHub("").GetHumanVersion()+"/"+ou+"/"+cn)
		context.PutString(CtxUserAgentString, fmt.Sprintf("Ozone/FCS/1.0 ou:%s cn:%s", ou, cn))
	} else {
		//resty.SetHeader("User-Agent", "OzoneFCS/"+version.NewGitHub("").GetHumanVersion())
		context.PutString(CtxUserAgentString, fmt.Sprint("Ozone/FCS/1.0"))
	}

	logrus.Tracef("TokenEndpoint auth method %s", config.tokenEndpointAuthMethod)
	return nil
}
