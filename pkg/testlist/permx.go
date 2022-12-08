package testlist

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"

	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/discovery"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/model"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/spec"
)

// TestCasePermission -
type TestCasePermission struct {
	ID     string   `json:"id,omitempty"`
	Perms  []string `json:"perms,omitempty"`
	Permsx []string `json:"permsx,omitempty"`
}

// RequiredTokens -
type RequiredTokens struct {
	Name            string   `json:"name,omitempty"`
	Token           string   `json:"token,omitempty"`
	IDs             []string `json:"ids,omitempty"`
	Perms           []string `json:"perms,omitempty"`
	Permsx          []string `json:"permsx,omitempty"`
	AccessToken     string
	ConsentURL      string
	ConsentID       string
	ConsentParam    string
	ConsentProvider string
	AccountID       string
	BaseURL         string
}

// TokenStore eats tokens
type TokenStore struct {
	currentID int
	store     []RequiredTokens
}

// GetRequiredTokensFromTests - Given a set of testcases with the permissions defined
// in the context using 'permissions' and 'permissions-excluded'
// provides a RequiredTokens structure which can be used to capture token requirements
func GetRequiredTokensFromTests(tcs []model.TestCase, specType spec.Type) (rt []RequiredTokens, err error) {
	switch specType {
	case spec.KsaAccount:
		fallthrough
	case spec.KsaLetter:
		fallthrough
	case spec.ObieAccount:
		tcp, err := getTestCasePermissions(tcs)
		if err != nil {
			return nil, err
		}
		rt, err = getRequiredTokens(tcp)
		if err != nil {
			return nil, err
		}
	case spec.ObiePayment:
		rt, err = GetPaymentPermissions(tcs)
	case spec.ObieCBPII:
		rt, err = GetCbpiiPermissions(tcs)
	case spec.ObieVRP:
		rt, err = GetVrpsPermissions(tcs)
	}
	return rt, err
}

// GetCbpiiPermissions -
func GetCbpiiPermissions(tests []model.TestCase) ([]RequiredTokens, error) {
	rt := make([]RequiredTokens, 0)
	ts := TokenStore{}
	ts.store = rt
	consentJobs := GetConsentJobs()
	for k, tc := range tests {
		ctx := tc.Context
		consentRequired, found := ctx.GetString("requestConsent")
		if found != nil {
			continue
		}
		if consentRequired == "true" {
			// get consentid
			consentID := GetConsentIDFromMatches(tc)
			rx := RequiredTokens{Name: ts.GetNextTokenName("cbpii"), ConsentParam: consentID, ConsentProvider: tc.ID}
			rt = append(rt, rx)
			logrus.Tracef("adding %s to consentJobs for cbpii: %s %s", tc.ID, tc.Input.Method, tc.Input.Endpoint)
			consentJobs.Add(tc)
		} else {
			tests[k].InjectBearerToken("$cbpii_ccg_token")
		}
	}
	requiredTokens, err := updateTokensFromConsent(rt, tests)
	if err != nil {
		return nil, err
	}

	return requiredTokens, nil
}

// GetPaymentPermissions - and annotate test cases with token ids
func GetPaymentPermissions(tests []model.TestCase) ([]RequiredTokens, error) {
	requiredTokens := getPaymentPermissions(tests, "payment")
	requiredTokens, err := updateTokensFromConsent(requiredTokens, tests)
	if err != nil {
		return nil, err
	}
	updateTestAuthenticationFromToken(tests, requiredTokens)

	return requiredTokens, nil
}

// GetVrpsPermissions - and annotate test cases with token ids
func GetVrpsPermissions(tests []model.TestCase) ([]RequiredTokens, error) {
	requiredTokens := getPaymentPermissions(tests, "vrps")
	requiredTokens, err := updateTokensFromConsent(requiredTokens, tests)
	if err != nil {
		return nil, err
	}
	updateTestAuthenticationFromToken(tests, requiredTokens)

	return requiredTokens, nil
}

// looks for post consent Tests that need to be run to get consentIds
func getPaymentPermissions(tcs []model.TestCase, tokenName string) []RequiredTokens {
	rt := make([]RequiredTokens, 0)
	ts := TokenStore{}
	ts.store = rt
	consentJobs := GetConsentJobs()
	for k, tc := range tcs {
		ctx := tc.Context
		consentRequired, found := ctx.GetString("requestConsent")
		if found != nil {
			continue
		}
		if consentRequired == "true" {
			// get consentid
			consentID := GetConsentIDFromMatches(tc)
			rx := RequiredTokens{Name: ts.GetNextTokenName(tokenName), ConsentParam: consentID, ConsentProvider: tc.ID}
			rt = append(rt, rx)
			logrus.Tracef("adding %s to consentJobs : %s %s", tc.ID, tc.Input.Method, tc.Input.Endpoint)
			consentJobs.Add(tc)
		} else {
			tcs[k].InjectBearerToken("$payment_ccg_token")
		}
	}

	return rt
}

// scans all payment test to make test against consent provider
func updateTokensFromConsent(rts []RequiredTokens, tcs []model.TestCase) ([]RequiredTokens, error) {
	for rtidx, rt := range rts {
		for _, test := range tcs {
			ctx := test.Context
			value, _ := ctx.GetString("consentId")
			if len(value) > 1 {
				if rt.ConsentParam == value[1:] {
					rt.IDs = append(rt.IDs, test.ID)
					rts[rtidx] = rt
				}
			}
		}
	}
	return rts, nil
}

// GetConsentIDFromMatches -
func GetConsentIDFromMatches(tc model.TestCase) string {
	matches := tc.Expect.ContextPut.Matches
	for _, m := range matches {
		if m.JSON == "Data.ConsentId" {
			return m.ContextName
		}
	}
	return ""
}

// GetTestCasePermissions -
func getTestCasePermissions(tcs []model.TestCase) ([]TestCasePermission, error) {
	tcps := []TestCasePermission{}
	for _, tc := range tcs {
		ctx := tc.Context
		perms, found := ctx.GetStringSlice("permissions")
		if found != nil {
			continue
		}
		permsx, _ := ctx.GetStringSlice("permissions-excluded")
		tcp := TestCasePermission{ID: tc.ID, Perms: perms, Permsx: permsx}
		tcps = append(tcps, tcp)
	}
	return tcps, nil
}

// GetRequiredTokens - gathers all tokens
// returns a list of tokens, each token has a list of permissions and a list of the tests that use those permissions
func getRequiredTokens(tcps []TestCasePermission) ([]RequiredTokens, error) {
	te := TokenStore{}
	for _, tcp := range tcps {
		te.createOrUpdate(tcp)
	}
	return te.store, nil
}

// MapTokensToTestCases - applies consented tokens to testcases
func MapTokensToTestCases(rt []RequiredTokens, tcs []model.TestCase) map[string]string {
	logrus.Debugln("MAP Tokens To Test Cases ...")
	logrus.Debugf("MapTokensToTestCases: required: %v", rt)

	tokenMap := map[string]string{}
	for k, tc := range tcs {
		tokenName, isEmptyToken, err := getRequiredTokenForTestcase(rt, tc.ID)
		if err != nil {
			logrus.Errorf("getRequiredTokenForTestCase Error: %s, %s, %t :%s", tc.ID, tokenName, isEmptyToken, err.Error())
			continue
		}
		if !isEmptyToken {
			logrus.Debugf("MapTokensToTests InjectBearerToken: %s, %s, %t", tc.ID, tokenName, isEmptyToken)
			tc.InjectBearerToken("$" + tokenName)
		}
		if strings.Contains(tc.Input.Endpoint, "letters-of-guarantee-consents") {
			tc.InjectBearerToken("$letter_ccg_token")
		}
		tcs[k] = tc
	}
	for _, v := range rt {
		tokenMap[v.Name] = v.Token
	}
	logrus.Debugf("MapTokensToTestCases: Mapped RequiredTokens to TestCases: %v", tokenMap)
	logrus.Debugln("END MAP Tokens To Test Cases ...")
	return tokenMap
}

// MapTokensToPaymentTestCases -
func MapTokensToPaymentTestCases(rt []RequiredTokens, tcs []model.TestCase, ctx *model.Context) {
	for k, test := range tcs {
		authCodeTokenRequired := requiresAuthCodeToken(test.ID, test.Input.Method, test.Input.Endpoint)

		if authCodeTokenRequired {
			logrus.Trace("MapTokensToPaymentTestCases: authCodeToken Required")
			tokenName, isEmptyToken, err := getRequiredTokenForPaymentTestcase(rt, test.ID)
			if err != nil {
				logrus.Warnf("no token for Payment testcase %s %s %s", test.ID, test.Input.Method, test.Input.Endpoint)
				continue
			}
			if !isEmptyToken {
				token, err := ctx.GetString(tokenName)
				if err == nil {
					test.InjectBearerToken(token)
				} else {
					test.InjectBearerToken("$" + tokenName)
				}
			}
		} else {
			if test.Input.Method == "GET" {
				test.InjectBearerToken("$payment_ccg_token")
				continue
			}
			useCCGToken, _ := test.Context.Get("useCCGToken")
			if useCCGToken == "yes" { // payment POSTs
				test.InjectBearerToken("$payment_ccg_token")
				continue
			}
		}
		tcs[k] = test
	}
}

// MapTokensToCBPIITestCases maps tokens retrieved after the consent acquisition flow
// maps them into test cases that require access tokens (ccg tokens)
func MapTokensToCBPIITestCases(rt []RequiredTokens, tcs []model.TestCase, ctx *model.Context) {
	for k, test := range tcs {
		authCodeTokenRequired := requiresCBPIIAuthCodeToken1(test.ID, test.Input.Method, test.Input.Endpoint)
		if authCodeTokenRequired {
			tokenName, isEmptyToken, err := getRequiredTokenForPaymentTestcase(rt, test.ID)
			if err != nil {
				logrus.Warnf("no token for CBPII testcase %s %s %s", test.ID, test.Input.Method, test.Input.Endpoint)
				continue
			}
			if !isEmptyToken {
				token, err := ctx.GetString(tokenName)
				if err == nil {
					test.InjectBearerToken(token)
				} else {
					test.InjectBearerToken("$" + tokenName)
				}
			}
		} else if test.Input.Method == "GET" && strings.Contains(test.ID, "CBPII") {
			test.InjectBearerToken("$cbpii_ccg_token")
			continue
		}
		tcs[k] = test
	}
}

// For Payments,
// Requires Auth Token if its a GET and contains 'funds-confirmation' in the URL OR
// A POST that doesn't contain 'consents' in the URL
func requiresAuthCodeToken(id, method, endpoint string) bool {
	if strings.ToUpper(method) == "GET" && strings.Contains(endpoint, "funds-confirmation") {
		logrus.Tracef("%s %s %s requires auth code token", id, method, endpoint)
		return true
	}
	if strings.ToUpper(method) == "POST" && strings.Contains(endpoint, "funds-confirmation") { // vrp
		logrus.Tracef("%s %s %s requires auth code token", id, method, endpoint)
		return true
	}
	if strings.ToUpper(method) == "POST" && !strings.Contains(endpoint, "consents") {
		logrus.Tracef("%s %s %s requires auth code token", id, method, endpoint)
		return true
	}

	return false
}

// For CBPII
func requiresCBPIIAuthCodeToken1(id, method, endpoint string) bool {
	authCodeEndpointsRegex := []discovery.Endpoint{
		{
			Path:   "^/funds-confirmations$",
			Method: "POST",
		},
	}
	for _, authCodeEndpoint := range authCodeEndpointsRegex {
		matched, err := regexp.MatchString(authCodeEndpoint.Path, endpoint)
		if err != nil {
			logrus.Warnf("unable to match endpoint regex %s with %s err %v", authCodeEndpoint.Path, endpoint, err)
			continue
		}
		if matched && strings.ToUpper(method) == authCodeEndpoint.Method {
			logrus.Tracef("%s %s %s requires auth code token", id, method, endpoint)
			return true
		}
	}

	return false
}

// gets token name from a testcase id
func getRequiredTokenForPaymentTestcase(rt []RequiredTokens, testcaseID string) (tokenName string, isEmptyToken bool, err error) {
	for _, v := range rt {
		for _, id := range v.IDs {
			if testcaseID == id {
				logrus.Tracef("%s requires token %s", testcaseID, v.Name)
				return v.Name, false, nil
			}
		}
	}
	return "", false, errors.New("token not found for " + testcaseID)
}

// gets token name from a testcase id
func getRequiredTokenForTestcase(rt []RequiredTokens, testcaseID string) (tokenName string, isEmptyToken bool, err error) {
	for _, v := range rt {
		if len(v.Perms) == 0 {
			return "", true, nil
		}
		for _, id := range v.IDs {
			if testcaseID == id {
				return v.Name, false, nil
			}
		}
	}
	return "", false, errors.New("token not found for " + testcaseID)
}

// GetNextTokenName -
func (te *TokenStore) GetNextTokenName(s string) string {
	te.currentID++
	return fmt.Sprintf("%sToken%4.4d", s, te.currentID)
}

// create or update TokenGethereer
func (te *TokenStore) createOrUpdate(tcp TestCasePermission) {

	if len(te.store) == 0 { // First time - no permissions - just add
		tpg := RequiredTokens{Name: te.GetNextTokenName("account"), IDs: []string{tcp.ID}, Perms: tcp.Perms, Permsx: tcp.Permsx}
		te.store = append(te.store, tpg)
		return
	}

	if len(tcp.Perms) == 0 && len(tcp.Permsx) == 0 {
		for idx, tgItem := range te.store {
			if len(tgItem.Perms) == 0 && len(tgItem.Permsx) == 0 {
				te.store[idx].IDs = append(te.store[idx].IDs, tcp.ID)
				return
			}
		}
		tpg := RequiredTokens{Name: te.GetNextTokenName("account"), IDs: []string{tcp.ID}, Perms: tcp.Perms, Permsx: tcp.Permsx}
		te.store = append(te.store, tpg)
	}

	for idx, tgItem := range te.store { // loop through each Gathered Item
		tcPermxConflict := false
		tcPermConflict := false

		// Check groupPermissions against testcaseExclusions
		for _, tgperm := range tgItem.Perms { // loop through all
			for _, tcpermx := range tcp.Permsx {
				if tgperm == tcpermx {
					tcPermxConflict = true
					break
				}
			}
			if tcPermxConflict {
				break
			}
		}
		if tcPermxConflict { //move onto next group item
			continue
		}

		// Check groupExclusions against testcasePermissions
		for _, tgpermx := range tgItem.Permsx {
			for _, tcperm := range tcp.Perms {
				if tgpermx == tcperm {
					tcPermConflict = true
					break
				}
			}
			if tcPermConflict {
				break
			}
		}
		if tcPermConflict {
			continue
		}
		newItem := addPermToGathererItem(tcp, tgItem)
		te.store[idx] = newItem
		return
	}
	tpg := RequiredTokens{Name: te.GetNextTokenName("account"), IDs: []string{tcp.ID}, Perms: tcp.Perms, Permsx: tcp.Permsx}
	te.store = append(te.store, tpg)

	return
}

func addPermToGathererItem(tp TestCasePermission, tg RequiredTokens) RequiredTokens {
	tg.IDs = append(tg.IDs, tp.ID)
	permsToAdd := []string{}
	permsxToAdd := []string{}
	for _, tgPerm := range tg.Perms {
		for _, tpPerm := range tp.Perms {
			if tpPerm == tgPerm {
				continue
			} else if tpPerm != "" {
				permsToAdd = append(permsToAdd, tpPerm)
			}
		}
	}
	for _, tgPermx := range tg.Permsx {
		for _, tpPermx := range tp.Permsx {
			if tpPermx == tgPermx {
				continue
			} else if tpPermx != "" {
				permsxToAdd = append(permsxToAdd, tpPermx)
			}
		}
	}
	tg.Perms = append(tg.Perms, permsToAdd...)
	tg.Perms = uniqueSlice(tg.Perms)
	tg.Permsx = append(tg.Permsx, permsxToAdd...)
	tg.Permsx = uniqueSlice(tg.Permsx)

	return tg
}

func uniqueSlice(inslice []string) []string {
	compressor := map[string]bool{}
	for _, v := range inslice {
		compressor[v] = true
	}
	tmpslice := []string{}
	for k := range compressor {
		tmpslice = append(tmpslice, k)
	}
	return tmpslice
}
