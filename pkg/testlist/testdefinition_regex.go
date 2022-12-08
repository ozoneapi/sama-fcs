package testlist

import (
	"encoding/json"
	"fmt"

	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/spec"
)

/*
	API Specs need defintions in this file so that API discovery file endpoints
	can be matched against what's in the spec.
	So we end up with a list of endpoints that are then used to filter the testcases
	so that only tests for the listed endpoints are run
*/

func getEndpointsRegexForSpec(specType spec.Type) []PathRegex {
	var regexPath []PathRegex

	switch specType { // All supported Specs Need to be listed here
	case spec.KsaAccount:
		regexPath = ksaAccountsRegex
	case spec.KsaLetter:
		regexPath = ksaLetterRegex
	case spec.ObieAccount:
		regexPath = obieAccountsRegex
	case spec.ObiePayment:
		regexPath = obiePaymentsRegex
	case spec.ObieCBPII:
		regexPath = obieCbpiiRegex
	case spec.ObieVRP:
		regexPath = obieVrpRegex
	default:
		regexPath = nil
	}
	return regexPath
}

func contains(s []TestDefinition, e TestDefinition) bool {
	for _, a := range s {
		if a.ID == e.ID {
			return true
		}
	}
	return false
}

// Utility to Dump Json
func dumpJSON(i interface{}) {
	var model []byte
	model, _ = json.MarshalIndent(i, "", "    ")
	fmt.Println(string(model))
}

var subPathx = "[a-zA-Z0-9_{}-]+" // url sub path regex

// PathRegex - regular express for path
type PathRegex struct {
	Regex  string
	Method string
	Name   string
}

var ksaAccountsRegex = []PathRegex{
	{
		Regex:  "^/account-access-consents$",
		Method: "POST",
		Name:   "Create an account access consent",
	},
	{
		Regex:  "^/account-access-consents/" + subPathx + "$",
		Method: "GET",
		Name:   "Get access consent by consent ID",
	},
	{
		Regex:  "^/account-access-consents/" + subPathx + "$",
		Method: "PATCH",
		Name:   "Patch an access consent by consent ID",
	},
	{
		Regex: "^/accounts$",
		Name:  "Get Accounts",
	},
	{
		Regex: "^/accounts/" + subPathx + "$",
		Name:  "Get Accounts Resource",
	},
	{
		Regex: "^/accounts/" + subPathx + "/balances$",
		Name:  "Get Balances Resource",
	},
	{
		Regex: "^/accounts/" + subPathx + "/beneficiaries$",
		Name:  "Get Beneficiaries Resource",
	},
	{
		Regex: "^/accounts/" + subPathx + "/direct-debits$",
		Name:  "Get Direct Debits Resource",
	},
	{
		Regex: "^/accounts/" + subPathx + "/parties$",
		Name:  "Get Party Resource",
	},
	{
		Regex: "^/accounts/" + subPathx + "/scheduled-payments$",
		Name:  "Get Scheduled Payment resource",
	},
	{
		Regex: "^/accounts/" + subPathx + "/standing-orders$",
		Name:  "Get Standing Orders resource",
	},
	{
		Regex: "^/accounts/" + subPathx + "/transactions$",
		Name:  "Get transactions resource",
	},
	{
		Regex: "^/parties$",
		Name:  "Get parties",
	},
}

var ksaLetterRegex = []PathRegex{
	{
		Regex: "^/letters-of-guarantee-consents$",
		Name:  "POST Letter of Guarantee consents",
	},
	{
		Regex: "^/letters-of-guarantee$",
		Name:  "POST Letter of Gurarantee",
	},
	{
		Regex: "^/letters-of-guarantee-consents/" + subPathx + "$",
		Name:  "",
	},
	{
		Regex: "^/letters-of-guarantee-consents/{ConsentId}",
		Name:  "Get/PATCH Letter of Guarantee",
	},
	{
		Regex: "^/letters-of-guarantee/" + subPathx + "$",
		Name:  "Get Letter of Guarantee",
	},
}

var obieAccountsRegex = []PathRegex{
	{
		Regex: "^/accounts$",
		Name:  "Get Accounts",
	},
	{
		Regex: "^/accounts/" + subPathx + "$",
		Name:  "Get Accounts Resource",
	},
	{
		Regex: "^/accounts/" + subPathx + "/balances$",
		Name:  "Get Balances Resource",
	},
	{
		Regex: "^/accounts/" + subPathx + "/beneficiaries$",
		Name:  "Get Beneficiaries Resource",
	},
	{
		Regex: "^/accounts/" + subPathx + "/direct-debits$",
		Name:  "Get Direct Debits Resource",
	},
	{
		Regex: "^/accounts/" + subPathx + "/offers$",
		Name:  "Get Offers Resource",
	},
	{
		Regex: "^/accounts/" + subPathx + "/party$",
		Name:  "Get Party Resource",
	},
	{
		Regex: "^/accounts/" + subPathx + "/product$",
		Name:  "Get Product Resource",
	},
	{
		Regex: "^/accounts/" + subPathx + "/scheduled-payments$",
		Name:  "Get Scheduled Payment resource",
	},
	{
		Regex: "^/accounts/" + subPathx + "/standing-orders$",
		Name:  "Get Standing Orders resource",
	},
	{
		Regex: "^/accounts/" + subPathx + "/statements$",
		Name:  "Get Statements Resource",
	},
	{
		Regex: "^/accounts/" + subPathx + "/statements/" + subPathx + "/file$",
		Name:  "Get statement files resource",
	},
	{
		Regex: "^/accounts/" + subPathx + "/statements/" + subPathx + "/transactions$",
		Name:  "Get statement transactions resource",
	},
	{
		Regex: "^/accounts/" + subPathx + "/transactions$",
		Name:  "Get transactions resource",
	},
	{
		Regex: "^/balances$",
		Name:  "Get Balances",
	},
	{
		Regex: "^/beneficiaries$",
		Name:  "Get Beneficiaries",
	},
	{
		Regex: "^/direct-debits$",
		Name:  "Get directory debits",
	},
	{
		Regex: "^/offers$",
		Name:  "Get Offers",
	},
	{
		Regex: "^/party$",
		Name:  "Get party",
	},
	{
		Regex: "^/products$",
		Name:  "Get Products",
	},

	{
		Regex: "^/scheduled-payments$",
		Name:  "Get Payments",
	},
	{
		Regex: "^/standing-orders$",
		Name:  "Get Orders",
	},
	{
		Regex: "^/statements$",
		Name:  "Get Statements",
	},
	{
		Regex: "^/transactions$",
		Name:  "Get Transactions",
	},
}

var obiePaymentsRegex = []PathRegex{
	{
		Regex:  "^/domestic-payment-consents$",
		Method: "POST",
		Name:   "Create a domestic payment consent",
	},
	{
		Regex:  "^/domestic-payment-consents/" + subPathx + "$",
		Method: "GET",
		Name:   "Get domestic payment consent by by consent ID",
	},
	{
		Regex:  "^/domestic-payment-consents/" + subPathx + "/funds-confirmation$",
		Method: "GET",
		Name:   "Get domestic payment consents funds confirmation, by consentID",
	},
	{
		Regex:  "^/domestic-payments$",
		Method: "POST",
		Name:   "Create a domestic payment",
	},
	{
		Regex:  "^/domestic-payments/" + subPathx + "$",
		Method: "GET",
		Name:   "Get domestic payment by domesticPaymentID",
	},
	{
		Regex:  "^/domestic-scheduled-payment-consents$",
		Method: "POST",
		Name:   "Create a domestic scheduled payment consent",
	},
	{
		Regex:  "^/domestic-scheduled-payment-consents/" + subPathx + "$",
		Method: "GET",
		Name:   "Get domestic scheduled payment consent by consentID",
	},
	{
		Regex:  "^/domestic-scheduled-payments$",
		Method: "POST",
		Name:   "Create a domestic scheduled payment",
	},
	{
		Regex:  "^/domestic-scheduled-payment/" + subPathx + "$",
		Method: "GET",
		Name:   "Get domestic scheduled payments by consentID",
	},
	{
		Regex:  "^/domestic-standing-order-consents$",
		Method: "POST",
		Name:   "Create a domestic standing order consent",
	},
	{
		Regex:  "^/domestic-standing-order-consents/" + subPathx + "$",
		Method: "GET",
		Name:   "Get domestic standing order consent by consentID",
	},
	{
		Regex:  "^/domestic-standing-orders$",
		Method: "POST",
		Name:   "Create a domestic standing order",
	},
	{
		Regex:  "^/domestic-standing-orders/" + subPathx + "$",
		Method: "GET",
		Name:   "Get domestic standing order by domesticStandingOrderID",
	},
	{
		Regex:  "^/international-payment-consents$",
		Method: "POST",
		Name:   "Create an international payment consent",
	},
	{
		Regex:  "^/international-payment-consents/" + subPathx + "$",
		Method: "GET",
		Name:   "Get international payment consent by consentID",
	},
	{
		Regex:  "^/international-payment-consents/" + subPathx + "/funds-confirmation$",
		Method: "GET",
		Name:   "Get international payment consent funds confirmation by consentID",
	},
	{
		Regex:  "^/international-payments$",
		Method: "POST",
		Name:   "Create an international payment",
	},
	{
		Regex:  "^/international-payments/" + subPathx + "$",
		Method: "GET",
		Name:   "Get international payment by internationalPaymentID",
	},
	{
		Regex:  "^/international-scheduled-payment-consents$",
		Method: "POST",
		Name:   "Create an international scheduled payment consent",
	},
	{
		Regex:  "^/international-scheduled-payment-consents/" + subPathx + "$",
		Method: "GET",
		Name:   "Get international scheduled payment consents by consentID",
	},
	{
		Regex:  "^/international-scheduled-payments/" + subPathx + "/funds-confirmation$",
		Method: "GET",
		Name:   "Get international scheduled payment funds confirmation by consentID",
	},
	{
		Regex:  "^/international-scheduled-payments$",
		Method: "POST",
		Name:   "Create an international scheduled payment",
	},
	{
		Regex:  "^/international-scheduled-payments/" + subPathx + "$",
		Method: "GET",
		Name:   "Create an international scheduled payment by internationalScheduledPaymentID",
	},
	{
		Regex:  "^/international-standing-order-consents$",
		Method: "POST",
		Name:   "Create international standing order consent",
	},
	{
		Regex:  "^/international-standing-order-consents/" + subPathx + "$",
		Method: "GET",
		Name:   "Get international standing order consent by consentID",
	},
	{
		Regex:  "^/international-standing-orders$",
		Method: "POST",
		Name:   "Create international standing order",
	},
	{
		Regex:  "^/international-standing-orders/" + subPathx + "$",
		Method: "GET",
		Name:   "Get an international standing order by internationalStandingOrderID",
	},
	{
		Regex:  "^/file-payment-consents$",
		Method: "POST",
		Name:   "Create a file payment consent",
	},
	{
		Regex:  "^/file-payment-consents/" + subPathx + "$",
		Method: "GET",
		Name:   "Get a file payment consent by consentID",
	},
	{
		Regex:  "^/file-payment-consents/" + subPathx + "/file$",
		Method: "POST",
		Name:   "Create a file payment consent file by consentID",
	},
	{
		Regex:  "^/file-payment-consents/" + subPathx + "/file$",
		Method: "GET",
		Name:   "Get a file payment consents file by consentID",
	},
	{
		Regex:  "^/file-payments$",
		Method: "POST",
		Name:   "Create a file payment",
	},
	{
		Regex:  "^/file-payments/" + subPathx + "$",
		Method: "GET",
		Name:   "Get a file payment by filePaymentID",
	},
	{
		Regex:  "^/file-payments/" + subPathx + "/report-file$",
		Method: "GET",
		Name:   "Get a file payment report file by filePaymentID",
	},
}

var obieCbpiiRegex = []PathRegex{
	{
		Regex:  "^/funds-confirmation-consents$",
		Method: "POST",
		Name:   "Create Funds Confirmation Consent",
	},
	{
		Regex:  "^/funds-confirmation-consents/" + subPathx + "$",
		Method: "GET",
		Name:   "Retrieve Funds Confirmation Consent",
	},
	{
		Regex:  "^/funds-confirmation-consents/" + subPathx + "$",
		Method: "DELETE",
		Name:   "Delete Funds Confirmation Consent",
	},
	{
		Regex:  "^/funds-confirmations$",
		Method: "POST",
		Name:   "Create Funds Confirmation",
	},
}

var obieVrpRegex = []PathRegex{
	{
		Regex:  "^/domestic-vrp-consents$",
		Method: "POST",
		Name:   "Create a domestic VRP consent",
	},
	{
		Regex:  "^/domestic-vrp-consents/" + subPathx + "$",
		Method: "GET",
		Name:   "Get domestic VRP consent by consent ID",
	},
	{
		Regex:  "^/domestic-vrp-consents/" + subPathx + "/funds-confirmation$",
		Method: "GET",
		Name:   "Get domestic VRP consents funds confirmation, by consentID",
	},
	{
		Regex:  "^/domestic-vrps$",
		Method: "POST",
		Name:   "Create a domestic VRP",
	},
	{
		Regex:  "^/domestic-vrps/" + subPathx + "$",
		Method: "GET",
		Name:   "Get domestic vrp by domesticVRPId",
	},
	{
		Regex:  "^/domestic-vrps/" + subPathx + "/payment-details$",
		Method: "POST",
		Name:   "Get domestic VRP payment details by domesticVRPId",
	},
}
