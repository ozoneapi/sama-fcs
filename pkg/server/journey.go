package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/auth"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/discovery"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/executors"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/executors/events"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/generation"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/model"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/server/models"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/spec"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/testlist"
)

var (
	errDiscoveryModelNotSet            = errors.New("error discovery model not set")
	errTestCasesNotGenerated           = errors.New("error test cases not generated")
	errTestCasesGenerated              = errors.New("error test cases already generated")
	errNotFinishedCollectingTokens     = errors.New("error not finished collecting tokens")
	errConsentIDAcquisitionFailed      = errors.New("ConsentId acquistion failed")
	errDynamicResourceAllocationFailed = errors.New("Dynamic Resource allocation failed")
	errNoTestCases                     = errors.New("No testcases were generated - please select a wider set of endpoints to test")
)

// Journey represents all possible steps for a user test conformance journey
//
// Happy path journey would look like:
// 1. SetCertificates - sets configuration to run test cases
// 2. SetDiscoveryModel - this validates and if successful set this as your discovery model
// 3. TestCases - Generates test cases, generates permission set requirements to run tests and starts a token collector
// 3.1 CollectToken - collects all tokens required to RunTest
// 4. RunTest - Runs triggers a background run on all generated test from previous steps, needs all token to be already collected
// 5. Results - returns a background process control, so we can monitor on finished tests
type Journey interface {
	SetDiscoveryModel(discoveryModel *discovery.Template) (discovery.ValidationFailures, error)
	DiscoveryModel() (discovery.Template, error)
	SetFilteredManifests(testlist.TestDefinitions)
	FilteredManifests() (testlist.TestDefinitions, error)
	TestCases() (generation.APIRun, error)
	CollectToken(code, state, scope string) error
	AllTokenCollected() bool
	RunTests() error
	StopTestRun()
	NewDaemonController()
	Results() executors.DaemonController
	SetConfig(config TppConfig) error
	ConditionalProperties() []discovery.ConditionalAPIProperties
	Events() events.Events
	TLSVersionResult() map[string]*discovery.TLSValidationResult
	SetUsePAR(parWkep string)
	UsePar() bool
}

// AppJourney - application controlled by this class
type AppJourney struct {
	generator             generation.Generator
	validator             discovery.Validator
	daemonController      executors.DaemonController
	journeyLock           *sync.Mutex
	apiRun                generation.APIRun
	testCasesRunGenerated bool
	collector             executors.TokenCollector
	allCollected          bool
	validDiscoveryModel   *discovery.Template
	context               model.Context
	log                   *logrus.Entry
	config                TppConfig
	events                events.Events
	permissions           map[spec.Type][]testlist.RequiredTokens
	testdefs              []testlist.TestDefinitions
	filteredManifests     testlist.TestDefinitions
	tlsValidator          discovery.TLSValidator
	conditionalProperties []discovery.ConditionalAPIProperties
	dynamicResourceIDs    bool
	usePar                bool
	parWkep               string
}

// NewJourney creates an instance for a user journey
func NewJourney(logger *logrus.Entry, generator generation.Generator,
	validator discovery.Validator, tlsValidator discovery.TLSValidator,
	dynamicResourceIDs bool) *AppJourney {
	return &AppJourney{
		generator:             generator,
		validator:             validator,
		daemonController:      executors.NewBufferedDaemonController(),
		journeyLock:           &sync.Mutex{},
		allCollected:          false,
		testCasesRunGenerated: false,
		context:               model.Context{},
		log:                   logger.WithField("module", "journey"),
		events:                events.NewEvents(),
		permissions:           make(map[spec.Type][]testlist.RequiredTokens),
		testdefs:              make([]testlist.TestDefinitions, 0),
		tlsValidator:          tlsValidator,
		dynamicResourceIDs:    dynamicResourceIDs,
	}
}

// NewDaemonController - calls StopTestRun and then sets new daemonController
// and new events on journey.
// This is a solution to prevent events being sent to a disconnected
// websocket instead of new websocket after the client reconnects.
func (wj *AppJourney) NewDaemonController() {
	wj.StopTestRun()

	wj.journeyLock.Lock()
	defer wj.journeyLock.Unlock()
	wj.daemonController = executors.NewBufferedDaemonController()
	wj.events = events.NewEvents()
}

// SetDiscoveryModel -
func (wj *AppJourney) SetDiscoveryModel(discoveryModel *discovery.Template) (discovery.ValidationFailures, error) {
	failures, err := wj.validator.Validate(discoveryModel)
	if err != nil {
		return nil, errors.Wrap(err, "journey.SetDiscoveryModel: error setting discovery model")
	}

	if !failures.Empty() {
		return failures, nil
	}

	wj.journeyLock.Lock()
	defer wj.journeyLock.Unlock()
	wj.validDiscoveryModel = discoveryModel
	wj.testCasesRunGenerated = false
	wj.allCollected = false

	if discoveryModel.APICollection.DiscoveryVersion == "v0.4.0" { // Conditional properties requires 0.4.0
		//TODO: remove this constraint once support for v0.3.0 discovery model is dropped
		conditionalAPIProperties, hasProperties, err := discovery.GetConditionalProperties(discoveryModel)
		if err != nil {
			return nil, errors.Wrap(err, "journey.SetDiscoveryModel: error processing conditional properties")
		}
		if hasProperties {
			wj.conditionalProperties = conditionalAPIProperties
			logrus.Tracef("conditionalProperties from discovery model: %#v", wj.conditionalProperties)
		} else {
			logrus.Trace("No Conditional Properties found")
		}
	}

	return discovery.NoValidationFailures(), nil
}

// SetUsePAR -
func (wj *AppJourney) SetUsePAR(parWkep string) {
	if len(parWkep) > 0 {
		wj.usePar = true
		wj.parWkep = parWkep
		wj.context.PutString("par_authorization_endpoint", parWkep)
		logrus.Infof("use par endpoint:%t, parWkep %s", wj.usePar, wj.parWkep)
	}
}

// UsePar ?
func (wj *AppJourney) UsePar() bool {
	return wj.usePar
}

// DiscoveryModel -
func (wj *AppJourney) DiscoveryModel() (discovery.Template, error) {
	wj.journeyLock.Lock()
	discoveryModel := wj.validDiscoveryModel
	wj.journeyLock.Unlock()

	if discoveryModel == nil {
		return discovery.Template{}, errors.New("journey.DiscoveryModel: discovery model not set yet")
	}
	return *discoveryModel, nil
}

// TLSVersionResult -
func (wj *AppJourney) TLSVersionResult() map[string]*discovery.TLSValidationResult {
	logger := wj.log.WithFields(logrus.Fields{
		"package":  "server",
		"module":   "journey",
		"function": "TLSVersionResult",
	})
	tlsValidationResult := make(map[string]*discovery.TLSValidationResult, len(wj.validDiscoveryModel.APICollection.APIDefinitions))
	logger.Warn("Skil TSLResultRubbish")
	return tlsValidationResult
}

// SetFilteredManifests -
func (wj *AppJourney) SetFilteredManifests(fmfs testlist.TestDefinitions) {
	wj.filteredManifests = fmfs
}

// FilteredManifests -
func (wj *AppJourney) FilteredManifests() (testlist.TestDefinitions, error) {
	return wj.filteredManifests, nil
}

// TestCases -
func (wj *AppJourney) TestCases() (generation.APIRun, error) {
	wj.journeyLock.Lock()
	defer wj.journeyLock.Unlock()
	logger := wj.log.WithFields(logrus.Fields{
		"package":  "server",
		"module":   "journey",
		"function": "TestCases",
	})

	if wj.validDiscoveryModel == nil {
		return generation.APIRun{}, errDiscoveryModelNotSet
	}

	if wj.testCasesRunGenerated {
		logger.WithFields(logrus.Fields{
			"err":                      errTestCasesGenerated,
			"wj.testCasesRunGenerated": wj.testCasesRunGenerated,
		}).Error("Error getting generation.TestCasesRun ...")
		return generation.APIRun{}, errTestCasesGenerated
	}

	jwksURI := auth.GetJWKSUri()
	if jwksURI != "" { // STORE jwks_uri from well known endpoint in journey context
		wj.context.PutString("jwks_uri", jwksURI)
	} else {
		logrus.Warn("JWKS URI is empty")
	}

	logrus.Warn("TLS Check disabled")

	config := wj.makeGeneratorConfig()
	apiCollection := wj.validDiscoveryModel.APICollection
	if len(apiCollection.APIDefinitions) > 0 { // default currently "v3.1" ... allow "v3.0"
		apiversions := DetermineAPIVersions(apiCollection.APIDefinitions)
		if len(apiversions) > 0 {
			wj.context.PutStringSlice("apiversions", apiversions)
		}
		// version string gets replaced in URLS like  "endpoint": "/open-banking/$api-version/aisp/account-access-consents",
		// TODO: check the version of the first spec needing to be the same as the others ...
		// In theory you might want a big discovery of loads of apis defined at different versions  ...
		version, err := spec.GetSemanticVersion(apiCollection.APIDefinitions[0].APISpecification.Version)
		if err != nil {
			logger.WithError(err).Error("parsing mapping version to semantic version model")
		}
		wj.config.apiVersion = fmt.Sprintf("v%d.%d", version.Major, version.Minor) // TODO Sort this out - this works for obie - not sure what else.
		// Should really come from baseResourceURL !!!!
		wj.context.PutString(CtxAPIVersion, wj.config.apiVersion)
		logger.WithField("version", wj.config.apiVersion).Info("API url version")
	}

	logger.Debug("generator.GenerateTests ...")
	logrus.Tracef("conditionalProperties from journey config: %#v", wj.config.conditionalProperties)
	wj.apiRun, wj.filteredManifests, wj.permissions = wj.generator.GenerateTests(config, apiCollection, &wj.context, wj.config.conditionalProperties, wj.log)

	tests := 0
	for _, sp := range wj.apiRun.APITests {
		tests += len(sp.TestCases)
	}
	if tests == 0 { // no tests to run
		logrus.Warn("No TestCases Generated!!!")
		return generation.APIRun{}, errNoTestCases
	}

	for _, spec := range wj.permissions {
		for _, required := range spec {
			logger.WithFields(logrus.Fields{
				"permission": required.Name,
				"idlist":     required.IDs,
			}).Debug("We have a permission ([]testlist.RequiredTokens)")
		}
	}

	tokenType := apiCollection.TokenAcquisition
	err := acquireTokens(wj, tokenType)
	if err != nil {
		return generation.APIRun{}, err
	}

	wj.testCasesRunGenerated = true

	logger.Tracef("SpecRun.SpecConsentRequirements: %#v", wj.apiRun.ConsentPermissions)

	for k := range wj.apiRun.APITests {
		logger.Tracef("SpecRun-Specification: %#v", wj.apiRun.APITests[k].APISpec)

	}
	return wj.apiRun, nil
}

func acquireTokens(wj *AppJourney, tokenType string) error {
	definition := wj.makeRunDefinition()
	usePar := wj.usePar
	consentIds, err := executors.GetConsents(tokenType, definition, &wj.context, &wj.apiRun, wj.permissions, usePar)
	if err != nil {
		logrus.Errorf("error %s Error from executors.GetPsuConsent", err)
		return errors.WithMessage(errConsentIDAcquisitionFailed, err.Error())
	}
	for k := range wj.permissions { // need to check that these array indexes still apply
		if k == "payments" {
			paymentpermissions := wj.permissions["payments"]
			if len(paymentpermissions) > 0 {
				for _, spec := range wj.apiRun.APITests {
					testlist.MapTokensToPaymentTestCases(paymentpermissions, spec.TestCases, &wj.context)
				}
			}
		}
		if k == "vrps" {
			vrpspermissions := wj.permissions["vrps"]
			if len(vrpspermissions) > 0 {
				for _, spec := range wj.apiRun.APITests {
					testlist.MapTokensToPaymentTestCases(vrpspermissions, spec.TestCases, &wj.context)
				}
			}
		}
		if k == "cbpii" {
			cbpiiPerms := wj.permissions["cbpii"]
			if len(cbpiiPerms) > 0 {
				for _, spec := range wj.apiRun.APITests {
					testlist.MapTokensToCBPIITestCases(cbpiiPerms, spec.TestCases, &wj.context)
				}
			}
		}
	}

	wj.createTokenCollector(consentIds, tokenType) // this thing triggers the consent screen population - by this time we have all the info...
	return nil
}

func (wj *AppJourney) tlsVersionCtxKey(discoveryItemName string) string {
	return fmt.Sprintf("tlsVersionForDiscoveryItem-%s", strings.ReplaceAll(discoveryItemName, " ", "-"))
}

func (wj *AppJourney) tlsValidCtxKey(discoveryItemName string) string {
	return fmt.Sprintf("tlsIsValidForDiscoveryItem-%s", strings.ReplaceAll(discoveryItemName, " ", "-"))
}

// CollectToken -
func (wj *AppJourney) CollectToken(code, state, scope string) error {
	wj.journeyLock.Lock()
	defer wj.journeyLock.Unlock()

	if !wj.testCasesRunGenerated {
		logrus.Error("CollectToken - cannot run - test cases not generated")
		return errTestCasesNotGenerated
	}

	accessToken, err := executors.ExchangeCodeForAccessToken(state, code, &wj.context)
	if err != nil {
		logrus.Errorf("CollectToken: ExchangeForAccessToken code:%s, state: %s, token: %s: %w", code, state, accessToken, err)
		return err
	}

	wj.context.PutString(state, accessToken)
	if state == "Token001" {
		logrus.Warnf("Setting access_token hack state == Token001")
		wj.context.PutString("access_token", accessToken) // tmp measure to get testcases running!!!
	}

	if wj.config.useDynamicResourceID {
		err := executors.GetDynamicResourceIds(state, accessToken, &wj.context, wj.permissions["accounts"])
		if err != nil {
			logrus.Errorf("CollectToken: GetDynamicResources: %w", err)
			return errDynamicResourceAllocationFailed
		}
	}

	return wj.collector.Collect(state, accessToken)
}

// AllTokenCollected -
func (wj *AppJourney) AllTokenCollected() bool {
	logrus.Debugf("All tokens collected %t", wj.allCollected)
	return wj.allCollected
}

func (wj *AppJourney) doneCollectionCallback() {
	logrus.Debug("Setting wj.allCollection=true")
	wj.allCollected = true
}

// RunTests -
func (wj *AppJourney) RunTests() error {
	logger := wj.log.WithField("function", "RunTests")

	if !wj.testCasesRunGenerated {
		logger.WithFields(logrus.Fields{
			"err": errTestCasesNotGenerated,
		}).Error("Error on starting run")
		return errTestCasesNotGenerated
	}

	if !wj.allCollected {
		logger.WithFields(logrus.Fields{
			"err": errNotFinishedCollectingTokens,
		}).Error("Error on starting run")
		return errNotFinishedCollectingTokens
	}

	if wj.config.useDynamicResourceID {
		for _, accountPermissions := range wj.permissions["accounts"] {
			// cycle over all test case ids for this account permission/token set
			for _, tcID := range accountPermissions.IDs {
				for i := range wj.apiRun.APITests {
					specType := wj.apiRun.APITests[i].APISpec.SpecType
					// isolate all testcases to be run that are from and 'account' spec type
					if specType == "accounts" {
						tc := wj.apiRun.APITests[i].TestCases
						// look for test cases matching the permission set test case list
						for j, test := range tc {
							if test.ID == tcID {
								resourceCtx := model.Context{}
								resourceCtx.PutString(CtxConsentedAccountID, accountPermissions.AccountID)
								// perform the dynamic resource id replacement
								test.ProcessReplacementFields(&resourceCtx, false)
								wj.apiRun.APITests[i].TestCases[j] = test
							}
						}
					}
				}
			}
		}
		// put a default accountid and statement id in the journey context for those tests that haven't got a token that can call /accounts
		wj.context.PutString(CtxConsentedAccountID, wj.config.resourceIDs.AccountIDs[0].AccountID)
		wj.context.PutString(CtxStatementID, wj.config.resourceIDs.StatementIDs[0].StatementID)
	}

	requiredTokens := wj.permissions

	for k := range wj.apiRun.APITests {
		specType := wj.apiRun.APITests[k].APISpec.SpecType
		testlist.MapTokensToTestCases(requiredTokens[specType], wj.apiRun.APITests[k].TestCases)
		wj.dumpJSON(wj.apiRun.APITests[k].TestCases)
	}

	runDefinition := wj.makeRunDefinition()
	runner := executors.NewTestCaseRunner(wj.log, runDefinition, wj.daemonController)
	err := runner.RunTestCases(&wj.context)
	return err
}

// Results -
func (wj *AppJourney) Results() executors.DaemonController {
	return wj.daemonController
}

// StopTestRun -
func (wj *AppJourney) StopTestRun() {
	wj.daemonController.Stop()
}

func (wj *AppJourney) createTokenCollector(consentIds executors.ConsentTokens, psuType string) {
	if psuType == "none" {
		wj.collector = executors.NewNullTokenCollector(consentIds, wj.doneCollectionCallback, wj.events, &wj.context)
		consentIdsToTestCaseRun(wj.log, consentIds, &wj.apiRun)

		for _, v := range consentIds {
			wj.collector.Collect(v.AccessToken, uuid.NewString())
		}

		wj.allCollected = true
	} else {
		if len(consentIds) > 0 {
			wj.collector = executors.NewTokenCollector(wj.log, consentIds, wj.doneCollectionCallback, wj.events)
			consentIdsToTestCaseRun(wj.log, consentIds, &wj.apiRun)

			wj.allCollected = false
		} else {
			wj.allCollected = true
		}
	}
	logrus.Debugf("TokenCollector status: allCollected:%t, consentIds %#v", wj.allCollected, consentIds)
}

func (wj *AppJourney) makeGeneratorConfig() generation.GeneratorConfig {
	return generation.GeneratorConfig{
		ClientID:              wj.config.clientID,
		Aud:                   wj.config.authorizationEndpoint,
		ResponseType:          "code id_token",
		Scope:                 "openid accounts",
		AuthorizationEndpoint: wj.config.authorizationEndpoint,
		RedirectURL:           wj.config.redirectURL,
		ResourceIDs:           wj.config.resourceIDs,
	}
}

func (wj *AppJourney) makeRunDefinition() executors.RunDefinition {
	return executors.RunDefinition{
		DiscoModel:    wj.validDiscoveryModel,
		APIRun:        wj.apiRun,
		SigningCert:   wj.config.certificateSigning,
		TransportCert: wj.config.certificateTransport,
	}
}

// TppConfig main configuration variables
type TppConfig struct {
	certificateSigning            auth.Certificate
	certificateTransport          auth.Certificate
	tppSignatureKID               string
	tppSignatureIssuer            string
	tppSignatureTAN               string
	clientID                      string
	clientSecret                  string
	tokenEndpoint                 string
	ResponseType                  string
	tokenEndpointAuthMethod       string
	authorizationEndpoint         string
	resourceBaseURL               string
	xXFAPIFinancialID             string
	xXFAPICustomerIPAddress       string
	redirectURL                   string
	resourceIDs                   model.ResourceIDs
	creditorAccount               models.Payment
	internationalCreditorAccount  models.Payment
	instructedAmount              models.InstructedAmount
	paymentFrequency              models.PaymentFrequency
	firstPaymentDateTime          string
	requestedExecutionDateTime    string
	currencyOfTransfer            string
	apiVersion                    string
	transactionFromDate           string
	transactionToDate             string
	requestObjectSigningAlgorithm string
	signingPrivate                string
	signingPublic                 string
	useDynamicResourceID          bool
	AcrValuesSupported            []string
	conditionalProperties         []discovery.ConditionalAPIProperties
	//cbpiiDebtorAccount            discovery.CBPIIDebtorAccount
	issuer            string
	letterOfGuarantee string
}

// SetConfig -
func (wj *AppJourney) SetConfig(config TppConfig) error {
	wj.journeyLock.Lock()
	defer wj.journeyLock.Unlock()

	wj.config = config
	wj.config.useDynamicResourceID = wj.dynamicResourceIDs // fed from environment variable 'dynres'=true/false
	err := PutParametersToJourneyContext(wj.config, wj.context)
	if err != nil {
		return err
	}

	wj.customTestParametersToJourneyContext()
	return nil
}

// ConditionalProperties retrieve conditional properties right after
// they have been set from the discovery model to the webJourney.ConditionalProperties
func (wj *AppJourney) ConditionalProperties() []discovery.ConditionalAPIProperties {
	return wj.conditionalProperties
}

// Events -
func (wj *AppJourney) Events() events.Events {
	return wj.events
}

func (wj *AppJourney) customTestParametersToJourneyContext() {
	if wj.validDiscoveryModel == nil {
		return
	}

	// assume ordering is prerun i.e. customtest run before other tests
	// for _, customTest := range wj.validDiscoveryModel.APICollection.CustomTests {
	// 	for k, v := range customTest.Replacements {
	// 		wj.context.PutString(k, v)
	// 	}
	// }
}

func consentIdsToTestCaseRun(log *logrus.Entry, consentIds []executors.ConsentToken, apiRun *generation.APIRun) {
	logrus.Debug("consentIdsToTestCaseRun: consentIds %v", consentIds)
	for _, v := range apiRun.ConsentPermissions {
		for x, permission := range v.NamedPermissions {
			for _, consentID := range consentIds {
				if consentID.TokenName == permission.Name {
					permission.ConsentURL = consentID.ConsentURL
					logrus.Debugf("set consentUrl for token: name: %s, url: %s,  %v", permission.Name, permission.ConsentURL, consentID)
					v.NamedPermissions[x] = permission
				}
			}
		}
	}
}

// Utility to Dump Json
func (wj *AppJourney) dumpJSON(i interface{}) {
	var model []byte
	model, _ = json.MarshalIndent(i, "", "    ")
	wj.log.Traceln(string(model))
}

// EnableDynamicResourceIDs is triggered by and environment variable dynids=true
func (wj *AppJourney) EnableDynamicResourceIDs() {
	wj.dynamicResourceIDs = true
}

// DetermineAPIVersions -
func DetermineAPIVersions(apis []discovery.APIDefinition) []string {
	apiversions := []string{}
	for _, v := range apis {
		v.APISpecification.SpecType, _ = spec.GetSpecType(v.APISpecification.Name)
		apiversions = append(apiversions, v.APISpecification.SpecType.String()+"_"+v.APISpecification.Version)
		logrus.Warnf("spectype %s, specversion %s", v.APISpecification.SpecType, v.APISpecification.Version)
	}
	return apiversions
}

var tlsCheck = true

// EnableTLSCheck -
func EnableTLSCheck(state bool) {
	tlsCheck = state
}
