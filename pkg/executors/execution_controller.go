package executors

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/auth"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/schema"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/schemaprops"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/spec"

	"github.com/go-resty/resty/v2"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"

	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/discovery"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/executors/results"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/generation"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/model"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/tracer"
)

// RunDefinition captures all the information required to run the test cases
type RunDefinition struct {
	DiscoModel    *discovery.Template
	APIRun        generation.APIRun
	SigningCert   auth.Certificate
	TransportCert auth.Certificate
}

// TestCaseRunner -
type TestCaseRunner struct {
	executor         TestCaseExecutor
	definition       RunDefinition
	daemonController DaemonController
	runningLock      *sync.Mutex
	running          bool
	usePar           bool
}

// NewTestCaseRunner -
func NewTestCaseRunner(logger *log.Entry, definition RunDefinition, daemonController DaemonController) *TestCaseRunner {
	return &TestCaseRunner{
		executor:         NewExecutor(),
		definition:       definition,
		daemonController: daemonController,
		runningLock:      &sync.Mutex{},
		running:          false,
	}
}

// NewConsentAcquisitionRunner -
func NewConsentAcquisitionRunner(definition RunDefinition, daemonController DaemonController, usePar bool) *TestCaseRunner {
	return &TestCaseRunner{
		executor:         NewExecutor(),
		definition:       definition,
		daemonController: daemonController,
		runningLock:      &sync.Mutex{},
		running:          false,
		usePar:           usePar,
	}
}

// NewExchangeComponentRunner -
func NewExchangeComponentRunner(definition RunDefinition, daemonController DaemonController) *TestCaseRunner {
	return &TestCaseRunner{
		executor:         NewExecutor(),
		definition:       definition,
		daemonController: daemonController,
		runningLock:      &sync.Mutex{},
		running:          false,
	}
}

// RunTestCases runs the testCases
func (r *TestCaseRunner) RunTestCases(ctx *model.Context) error {
	r.runningLock.Lock()
	defer r.runningLock.Unlock()
	if r.running {
		return errors.New("test cases runner already running")
	}
	r.running = true
	logrus.Debug("What's going on here?")
	go r.runTestCases(ctx)
	logrus.Debug("What's going on here2")
	return nil
}

// GetHeadlessConsent -
func (r *TestCaseRunner) GetHeadlessConsent(spectype spec.Type, item ConsentToken, ctx *model.Context, consentType string, consentIDChannel chan<- ConsentToken) error {
	r.runningLock.Lock()
	defer r.runningLock.Unlock()
	if r.running {
		return errors.New("GetHeadlessConsent runner already running")
	}
	r.running = true
	log.Tracef("GetHeadlessConsent token:%s, url: %s, perissions: %s", item.TokenName, item.ConsentURL, item.Permissions)
	go r.getConsent(spectype, item, ctx, consentType, consentIDChannel)

	return nil
}

// GetConsent -
func (r *TestCaseRunner) GetConsent(spectype spec.Type, item ConsentToken, ctx *model.Context, consentType string, consentIDChannel chan<- ConsentToken) error {
	r.runningLock.Lock()
	defer r.runningLock.Unlock()
	if r.running {
		return errors.New("GetConsent runner already running")
	}
	r.running = true
	log.Tracef("getConsent token:%s, url: %s, perissions: %s", item.TokenName, item.ConsentURL, item.Permissions)
	go r.getConsent(spectype, item, ctx, consentType, consentIDChannel)

	return nil
}

func (r *TestCaseRunner) runTestCases(ctx *model.Context) {
	err := r.executor.SetCertificates(r.definition.SigningCert, r.definition.TransportCert)
	if err != nil {
		log.Errorf("runTestCases: setCerts %w", err)
	}

	ruleCtx := r.makeRuleCtx(ctx)

	for _, spec := range r.definition.APIRun.APITests {
		r.executeSpecTests(spec, ruleCtx) // Run Tests for each spec
	}

	collector := schemaprops.GetPropertyCollector()
	r.daemonController.AddResponseFields(collector.OutputJSON())

	r.daemonController.SetCompleted()

	r.setRunning(false)
}

func (r *TestCaseRunner) getConsent(stype spec.Type, item ConsentToken, ctx *model.Context, consentType string, consentIDChannel chan<- ConsentToken) {
	err := r.executor.SetCertificates(r.definition.SigningCert, r.definition.TransportCert)
	if err != nil {
		log.Errorf("running consent acquisition async %w", err)
	}

	compCtx := r.makeRuleCtx(ctx)
	compCtx.PutString("consent_id", item.TokenName)
	compCtx.PutString("token_name", item.TokenName)
	compCtx.PutString("permission_list", item.Permissions)

	var comp model.Component

	// Check for MTLS vs client basic auth
	authMethod, err := ctx.GetString("token_endpoint_auth_method")
	if err != nil {
		authMethod = auth.ClientSecretBasic
	}

	if consentType == "psu" || consentType == "mobile" {
		if stype == spec.ObieAccount {
			comp, err = model.LoadComponent("PSUConsentProviderComponent.json")
			if err != nil {
				r.AppMsg("Load PSU Component Failed: " + err.Error())
				r.setRunning(false)
				return
			}
		}
		if stype == spec.KsaAccount {
			par, _ := ctx.GetString("par_authorization_endpoint")
			accountEndpointurl, err := ctx.GetString(stype.BaseURLID())
			if err != nil {
				r.AppMsg("Load PSU Component specType BaseURL failure: " + err.Error())
				r.setRunning(false)
				return
			}
			url, err := url.Parse(accountEndpointurl)
			if err != nil {
				r.AppMsg("Load PSU Component Failed baseurl failure: " + err.Error())
				r.setRunning(false)
				return
			}
			compCtx.PutString("account_access_consent_endpoint", url.Path+"/account-access-consents") //TODO: Need to sort this out ... parameterise correctly

			var ksaConsentComponentName string
			if len(par) > 0 {
				ksaConsentComponentName = "PSU_KSAAccount_PAR_Provider.json"
			} else {
				ksaConsentComponentName = "PSU_KSAAccount_ConsentProvider.json"
			}
			comp, err = model.LoadComponent(ksaConsentComponentName)
			if err != nil {
				logrus.Errorf("LoadComponent: %s - n %w", ksaConsentComponentName, err)
				r.AppMsg("Load PSU Component Failed: " + err.Error())
				r.setRunning(false)
				return
			}
		}
		if stype == spec.KsaLetter {
			par, _ := ctx.GetString("par_authorization_endpoint")
			letterEndpointurl, err := ctx.GetString(stype.BaseURLID())
			if err != nil {
				r.AppMsg("Load PSU Component specType BaseURL failure for LTG: " + err.Error())
				r.setRunning(false)
				return
			}
			url, err := url.Parse(letterEndpointurl)
			if err != nil {
				r.AppMsg("Load PSU Component Failed baseurl  for LTG failure: " + err.Error())
				r.setRunning(false)
				return
			}
			compCtx.PutString("letter_access_consent_endpoint", url.Path+"/letters-of-guarantee-consents")
			ltgFormData, err := ctx.GetString("letterOfGuarantee")
			if err == nil && len(ltgFormData) > 0 {
				logrus.Info("Using letter of guarantee input Form data length %d", len(ltgFormData))
				compCtx.PutString("lg-consentdata", ltgFormData)
			} else {
				logrus.Info("Using default letter of guarantee post consent data")
				compCtx.PutString("lg-consentdata", lgconsentData)
			}

			var ksaLetterComponentName = "PSU_KSALetter_PAR_Provider.json"
			if len(par) == 0 { // PAR endpoint not available
				r.AppMsg("Load LetterOfGuarantee LTG failure: par not supported - cannot continue")
				r.setRunning(false)
				return
			}
			comp, err = model.LoadComponent(ksaLetterComponentName)
			if err != nil {
				logrus.Errorf("LoadComponent: %s - n %w", ksaLetterComponentName, err)
				r.AppMsg("Load PSU Component Failed to load LTG component: " + err.Error())
				r.setRunning(false)
				return
			}
		}
	} else {
		comp, err = model.LoadComponent("headlessTokenProviderProviderComponent.json")
		if err != nil {
			r.AppMsg("Load HeadlessConsent Component Failed: " + err.Error())
			r.setRunning(false)
			return
		}
	}

	err = comp.ValidateParameters(compCtx) // correct parameters for component exist in context
	if err != nil {
		msg := fmt.Sprintf("component execution error: component (%s) cannot ValidateParameters: %s", comp.Name, err.Error())
		r.AppMsg(msg)
		r.setRunning(false)
		return
	}

	for k, v := range comp.GetTests() {
		v.ProcessReplacementFields(compCtx, true)
		v.Validator = schema.NewNullValidator()
		comp.Tests[k] = v
	}

	r.executeComponentTests(&comp, compCtx, item, consentIDChannel, authMethod)
	clientGrantToken, err := compCtx.GetString("client_access_token")
	if err == nil {
		log.StandardLogger().WithFields(log.Fields{
			"clientGrantToken": clientGrantToken,
		}).Debugf("Setting client_access_token")
		ctx.PutString("client_access_token", clientGrantToken)
		if stype == spec.KsaLetter {
			ctx.Put("letter_ccg_token", clientGrantToken)
			letterConsentID, err := compCtx.GetString("post-letter-consent-id")
			if err != nil {
				logrus.Errorf("Cannot find 'post-letter-consent-id in component context")
			} else {
				ctx.Put("post-letter-consent-id", letterConsentID)
			}
		}
	}

	r.setRunning(false)
}

func (r *TestCaseRunner) executeComponentTests(comp *model.Component, ctx *model.Context, item ConsentToken, consentIDChannel chan<- ConsentToken, authMethod string) {
	log.Debug("executeComponentTests: start")
	var sentConsent bool
	// Loop over all tests in the Component - assuming original ordering
	for _, tc := range comp.Tests {
		if r.daemonController.ShouldStop() {
			log.Debug("stop component test run received, aborting runner")
			return
		}
		// set the CCG auth method for tests called #compPsuConsent01 or parAuth
		if tc.ID == "#compPsuConsent01" || tc.ID == "parAuth" || strings.Contains(strings.ToLower(tc.ID), strings.ToLower("authmethod")) {
			switch authMethod {
			case auth.ClientSecretBasic:
				tc.Input.SetHeader("authorization", "Basic $basic_authentication")
			case auth.TLSClientAuth:
				clientid, err := ctx.GetString("client_id")
				if err != nil {
					log.Errorf("TlsClientAuth: cannot local client_id: authmethod:%s %w", authMethod, err)
					continue
				}
				tc.Input.SetFormField("client_id", clientid)
			case auth.PrivateKeyJwt:
				clientID, err := ctx.GetString("client_id")
				if err != nil {
					log.Errorf("cannot locate client_id to populate form field %s, %w", authMethod, err)
					continue
				}
				tokenEndpoint, err := ctx.GetString("token_endpoint")
				if err != nil {
					log.Errorf("cannot locate token_endpoint to populate form field %s, %w", authMethod, err)
				}

				if tc.Input.Claims == nil {
					tc.Input.Claims = map[string]string{}
				}
				// https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
				// iss
				// REQUIRED. Issuer. This MUST contain the client_id of the OAuth Client.
				// sub
				// REQUIRED. Subject. This MUST contain the client_id of the OAuth Client.
				// aud
				// REQUIRED. Audience. The aud (audience) Claim. Value that identifies the Authorization Server as an intended audience. The Authorization Server MUST verify that it is an intended audience for the token. The Audience SHOULD be the URL of the Authorization Server's Token Endpoint.
				tc.Input.Claims["iss"] = clientID
				tc.Input.Claims["sub"] = clientID
				tc.Input.Claims["aud"] = tokenEndpoint
				clientAssertion, err := tc.Input.GenerateRequestToken(ctx)
				if err != nil {
					log.Errorf("failed to GenerateRequestToken %s, %w", tc.ID, err)
					continue
				}
				tc.Input.SetFormField(auth.ClientAssertionType, auth.ClientAssertionTypeValue)
				tc.Input.SetFormField(auth.ClientAssertion, clientAssertion)
			default:
				log.Errorf("Unsupported token_endpoint_auth_method %s", tc.ID)
				continue
			}
		}
		logrus.Infof("COMPONENT - JOB: %s", tc.ID)
		testResult := r.executeTest(tc, ctx)
		logrus.Infof("COMPONENT - JOB RUN : %s", tc.ID)

		r.daemonController.AddResult(testResult)

		// Populate the Consent URLs screen!!
		// Typically 3 tests are run in a consentComponent
		// The last test is a dummy test who's purpose is to create a consentUrl
		// put the consent_url in the context
		// then this section of code looks for the consent_url in the context and if found
		//   populates and sends a TokenConsentIdItem to the consentIdChannel <- item
		//   hmmm....
		// so for PAR, we need to simply create a consent url in the context which triggers this behaviour
		// sentConsent means we only do this once per set of component tests
		if testResult.Pass && !sentConsent {
			var consentURL string
			log.Debugf("executeComponentTests: Checking if there is a consentURL generated %#v", item)
			consentURL, err := ctx.GetString("consent_url")
			if err == model.ErrNotFound {
				log.Debugf("looking for consent_url in response from %s - not found continue", tc.ID)
				continue
			}
			log.Debugf("executeComponentTests: Found consent_url from %s ...", tc.ID)
			item.ConsentURL = consentURL
			consentID, err := ctx.GetString(item.TokenName)
			if err == model.ErrNotFound {
				log.Warnf("no consentID in context for item.TokenName %s", item.TokenName)
			}
			item.ConsentID = consentID
			log.Debugf("executeComponentTests: Sending item (TokenConsentIDItem) to consentIDChannel %#v", item)
			consentIDChannel <- item
			sentConsent = true
		} else if len(testResult.Fail) > 0 {
			item.Err = testResult.Fail[0]
			log.Debugf("Sending failed itom to consentIDChannel %#v", item)
			consentIDChannel <- item
		}
	}
}

func (r *TestCaseRunner) setRunning(state bool) {
	log.Debug("acquiring runningLock")
	r.runningLock.Lock()
	log.Debug("acquired runningLock")
	defer func() {
		log.Debug("releasing runningLock")
		r.runningLock.Unlock()

	}()
	r.running = false

	// r.runningLock.Lock()
	// r.running = state
	// r.runningLock.Unlock()
}

func (r *TestCaseRunner) makeRuleCtx(ctx *model.Context) *model.Context {
	ruleCtx := &model.Context{}
	ruleCtx.PutContext(ctx)
	return ruleCtx
}

func (r *TestCaseRunner) executeSpecTests(spec generation.APITests, ruleCtx *model.Context) {
	collector := schemaprops.GetPropertyCollector()
	collector.SetCollectorAPIDetails(spec.APISpec.Name, spec.APISpec.Version)

	for _, testcase := range spec.TestCases {
		if r.daemonController.ShouldStop() {
			log.Info("stop test run received, aborting runner")
			return
		}
		ruleCtx.DumpContext("ruleCtx before: " + testcase.ID)
		testResult := r.executeTest(testcase, ruleCtx)
		r.daemonController.AddResult(testResult)
	}
}

func (r *TestCaseRunner) executeTest(tc model.TestCase, ruleCtx *model.Context) results.TestCase {
	log.Debugf("executeTest: start %s", tc.ID)
	req, err := tc.Prepare(ruleCtx)
	if err != nil {
		log.Errorf("executeTest: Prepare for %s returned %s", tc.ID, err.Error())
		return results.NewTestCaseFail(tc.ID, results.NoMetrics(), []error{err}, tc.Input.Endpoint, tc.APIName, tc.APIVersion, tc.Detail, tc.RefURI, tc.StatusCode)
	}
	resp, metrics, err := r.executor.ExecuteTestCase(req, &tc, ruleCtx)
	if err != nil {
		log.Errorf("executeTest: %s Failed %w", tc.ID, err)
		return results.NewTestCaseFail(tc.ID, metrics, []error{err}, tc.Input.Endpoint, tc.APIName, tc.APIVersion, tc.Detail, tc.RefURI, tc.StatusCode)
	}
	tc.StatusCode = resp.Status()
	result, errs := tc.Validate(resp, ruleCtx)
	if errs != nil {
		detailedErrors := detailedErrors(errs, resp)
		log.Errorf("executeTest: %s Validate Failed %w", tc.ID, err)
		log.Errorf("Details errors %#v", detailedErrors)
		return results.NewTestCaseFail(tc.ID, metrics, detailedErrors, tc.Input.Endpoint, tc.APIName, tc.APIVersion, tc.Detail, tc.RefURI, tc.StatusCode)
	}

	log.Infof("Test %s result %t", tc.ID, result)

	return results.NewTestCaseResult(tc.ID, result, metrics, []error{}, tc.Input.Endpoint, tc.APIName, tc.APIVersion, tc.Detail, tc.RefURI, tc.StatusCode)
}

// DetailError -
type DetailError struct {
	EndpointResponseCode int    `json:"endpointResponseCode"`
	EndpointResponse     string `json:"endpointResponse"`
	TestCaseMessage      string `json:"testCaseMessage"`
}

func (de DetailError) Error() string {
	j, _ := json.Marshal(de)

	return string(j)
}

func detailedErrors(errs []error, resp *resty.Response) []error {
	detailedErrors := []error{}
	for _, err := range errs {
		detailedError := DetailError{
			EndpointResponseCode: resp.StatusCode(),
			EndpointResponse:     string(resp.Body()),
			TestCaseMessage:      err.Error(),
		}
		detailedErrors = append(detailedErrors, detailedError)
	}
	return detailedErrors
}

func passText() map[bool]string {
	return map[bool]string{
		true:  "PASS",
		false: "FAIL",
	}
}

func logWithTestCase(logger *log.Entry, tc model.TestCase) *log.Entry {
	return logger.WithFields(log.Fields{
		"TestCase.Name":              tc.Name,
		"TestCase.Input.Method":      tc.Input.Method,
		"TestCase.Input.Endpoint":    tc.Input.Endpoint,
		"TestCase.Expect.StatusCode": tc.Expect.StatusCode,
	})
}

func logWithMetrics(logger *log.Entry, metrics results.Metrics) *log.Entry {
	return logger.WithFields(log.Fields{
		"responsetime": fmt.Sprintf("%v", metrics.ResponseTime),
		"responsesize": metrics.ResponseSize,
	})
}

// AppMsg - application level trace
func (r *TestCaseRunner) AppMsg(msg string) string {
	tracer.AppMsg("TestCaseRunner", msg, r.String())
	return msg
}

// AppErr - application level trace error msg
func (r *TestCaseRunner) AppErr(msg string) error {
	tracer.AppErr("TestCaseRunner", msg, r.String())
	return errors.New(msg)
}

// String - object represetation
func (r *TestCaseRunner) String() string {
	bites, err := json.MarshalIndent(r, "", "    ")
	if err != nil {
		// String() doesn't return error but still want to log as error to tracer ...
		return r.AppErr(fmt.Sprintf("error converting TestCaseRunner  %s", err.Error())).Error()
	}
	return string(bites)
}

const lgconsentData = `{"iss":"","exp":0,"nbf":0,"aud":["string"],"message":{"Data":{"AuthExpirationDateTime":"2023-11-29T06:49:19.659Z","mt798":{"CustomerReferenceNumber":"XYZ999","MessageCreationDateTime":"2022-11-29T06:49:19.659Z","KindOfGuarantee":"GUAR","TypeOfGuarantee":"TEND","FormOfGuarantee":"DIRC","WordingOfGuarantee":"STND","SpecialTerms":"EFCT","LanguageOfStandardWording":"en","ProjectName":"string","ProjectNumber":"string","Applicant":{"Name":"string","CommercialRegistrationNumber":0,"ApplicantIdentifierType":"string","ApplicantNumber":"string","Address":{"AddressType":"KSAOB.Business","ShortAddress":"string","BuildingNumber":"string","UnitNumber":10,"StreetName":"string","SecondaryNumber":"stri","District":"string","PostalCode":"string","City":"string","Country":"MM"}},"GuaranteeAmount":{"Type":"PRIN","Amount":"4","Currency":"SAR"},"ValidityType":"LIMT","ValidityExpiryDate":"2022-11-29T06:49:19.659Z","DeliveryOfOriginalGuarantee":"COUR","DeliveryTo":"BENE","DeliveryAddress":{"Name":"string","Address":{"AddressType":"KSAOB.Business","ShortAddress":"string","BuildingNumber":"string","UnitNumber":10,"StreetName":"string","SecondaryNumber":"stri","District":"string","PostalCode":"string","City":"string","Country":"VW"}},"Beneficiary":{"Name":"string","CommercialRegistrationNumber":0,"BeneficiaryIdentifierType":"string","BeneficiaryNumber":"string","Address":{"AddressType":"KSAOB.Business","ShortAddress":"string","BuildingNumber":"string","UnitNumber":10,"StreetName":"string","SecondaryNumber":"stri","District":"string","PostalCode":"string","City":"string","Country":"WC"}},"LiabilityDetails":"Pumps and Equipment","Reference":"TEND","ReferenceDate":"2022-11-29T06:49:19.659Z","ReferenceDate1":"2022-11-29T06:49:19.659Z","ReferenceDate2":"2022-11-29T06:49:19.659Z","TotalOrderAmount":{"Amount":"86436476429","Currency":"SAR"},"GuaranteeValueInPercent":10,"CustomerContact":"John Doe","BeneficiaryContact":"Jane Bloggs","BankReferenceNumber":"string","TransactionReferenceNumber":"NONREF","FurtherIdentification":"ISSUE","ApplicableRules":"NONE","ChargesAndFees":"string","DetailsOfGuarantee":"Performance Guarantee No . PGFFA0815.We have been informed that you, Mining PLC, Main Road, Riyadh, hereinafter called the BUYER have concluded the contract No. ABC123 of 05th February 2022, hereinafter called the CONTRACT, with Pumps Riyadh, KSA, hereinafter called the SELLER, according to which the SELLER will deliver to the BUYER pumps and equipment, in the total value of SAR 500.000,00. As agreed the SELLER has to provide a bank guarantee in favour of the BUYER, amounting to 10 percent of the total value, i.e. SAR 50.000,00 , to cover the fulfilment of the SELLER’s obligations under the CONTRACT.In consideration of the aforesaid, we, Bank of Acme, Riyadh, hereby issue the guarantee on behalf of the SELLER towards the BUYER to the maximum amount of SAR 50.000,00 (in words: SAR fifty thousand 00/100) and undertake irrevocably without consideration of any objections and defences of the SELLER or third parties and irrespective of the validity and legal effect of the CONTRACT and waiving any objections arising there from to pay to the BUYER any amount claimed from us by the BUYER up to the maximum amount of this guarantee upon receipt of the BUYER's first demand in writing, in which the BUYER simultaneously confirms that the SELLER is in breach of its obligations towards the BUYER under the CONTRACT.The obligation under this guarantee shall expire on 31st December 2022.Any claim for payment complying with the above conditions must be received by us within the validity period of this guarantee. This guarantee shall be governed by the law of KSA. Exclusive place of jurisdiction shall be KSA, Saudi Arabia.","TermsAndConditions":"string","LetterOfGuaranteeStartDate":"2022-11-29T06:49:19.660Z"}},"Subscription":{"Webhook":{"Url":"https://api.tpp.com/webhook/callbackUrl","IsActive":false}}}}`
const lgconsent1Data = `{"iss":"","exp":0,"nbf":0,"aud":["string"],"message":{"Data":{"AuthExpirationDateTime":"2023-11-29T06:49:19.659Z","mt798":{"CustomerReferenceNumber":"XYZ999","MessageCreationDateTime":"2022-11-29T06:49:19.659Z","KindOfGuarantee":"GUAR","TypeOfGuarantee":"TEND","FormOfGuarantee":"DIRC","WordingOfGuarantee":"STND","SpecialTerms":"EFCT","LanguageOfStandardWording":"en","ProjectName":"string","ProjectNumber":"string","Applicant":{"Name":"string","CommercialRegistrationNumber":0,"ApplicantIdentifierType":"string","ApplicantNumber":"string","Address":{"AddressType":"KSAOB.Business","ShortAddress":"string","BuildingNumber":"string","UnitNumber":10,"StreetName":"string","SecondaryNumber":"stri","District":"string","PostalCode":"string","City":"string","Country":"MM"}},"GuaranteeAmount":{"Type":"PRIN","Amount":"4","Currency":"SAR"},"ValidityType":"LIMT","ValidityExpiryDate":"2022-11-29T06:49:19.659Z","DeliveryOfOriginalGuarantee":"COUR","DeliveryTo":"BENE","DeliveryAddress":{"Name":"string","Address":{"AddressType":"KSAOB.Business","ShortAddress":"string","BuildingNumber":"string","UnitNumber":10,"StreetName":"string","SecondaryNumber":"stri","District":"string","PostalCode":"string","City":"string","Country":"VW"}},"Beneficiary":{"Name":"string","CommercialRegistrationNumber":0,"BeneficiaryIdentifierType":"string","BeneficiaryNumber":"string","Address":{"AddressType":"KSAOB.Business","ShortAddress":"string","BuildingNumber":"string","UnitNumber":10,"StreetName":"string","SecondaryNumber":"stri","District":"string","PostalCode":"string","City":"string","Country":"WC"}},"LiabilityDetails":"Pumps and Equipment","Reference":"TEND","ReferenceDate":"2022-11-29T06:49:19.659Z","ReferenceDate1":"2022-11-29T06:49:19.659Z","ReferenceDate2":"2022-11-29T06:49:19.659Z","TotalOrderAmount":{"Amount":"86436476429","Currency":"SAR"},"GuaranteeValueInPercent":10,"CustomerContact":"John Doe","BeneficiaryContact":"Jane Bloggs","BankReferenceNumber":"string","TransactionReferenceNumber":"NONREF","FurtherIdentification":"ISSUE","ApplicableRules":"NONE","ChargesAndFees":"string","DetailsOfGuarantee":"Performance Guarantee No . PGFFA0815.We have been informed that you, Mining PLC, Main Road, Riyadh, hereinafter called the BUYER have concluded the contract No. ABC123 of 05th February 2022, hereinafter called the CONTRACT, with Pumps Riyadh, KSA, hereinafter called the SELLER, according to which the SELLER will deliver to the BUYER pumps and equipment, in the total value of SAR 500.000,00. As agreed the SELLER has to provide a bank guarantee in favour of the BUYER, amounting to 10 percent of the total value, i.e. SAR 50.000,00 , to cover the fulfilment of the SELLER’s obligations under the CONTRACT.In consideration of the aforesaid, we, Bank of Acme, Riyadh, hereby issue the guarantee on behalf of the SELLER towards the BUYER to the maximum amount of SAR 50.000,00 (in words: SAR fifty thousand 00/100) and undertake irrevocably without consideration of any objections and defences of the SELLER or third parties and irrespective of the validity and legal effect of the CONTRACT and waiving any objections arising there from to pay to the BUYER any amount claimed from us by the BUYER up to the maximum amount of this guarantee upon receipt of the BUYER's first demand in writing, in which the BUYER simultaneously confirms that the SELLER is in breach of its obligations towards the BUYER under the CONTRACT.The obligation under this guarantee shall expire on 31st December 2022.Any claim for payment complying with the above conditions must be received by us within the validity period of this guarantee. This guarantee shall be governed by the law of KSA. Exclusive place of jurisdiction shall be KSA, Saudi Arabia.","TermsAndConditions":"string","LetterOfGuaranteeStartDate":"2022-11-29T06:49:19.660Z"},"ConsentId":"urn:SAMA2:klg-e7947cc0-8392-4dac-8e5f-5ff96fe8cd24","Status":"AwaitingAuthorization","CreationDateTime":"2022-12-07T09:50:06.252Z","StatusUpdateDateTime":"2022-12-07T09:50:06.252Z"},"Subscription":{"Webhook":{"Url":"https://api.tpp.com/webhook/callbackUrl","IsActive":false}},"Links":{"Self":"https://rs1.uat.openbanking.sa/open-banking/letter-of-guarantee/2022.11.01-final/letters-of-guarantee-consents/urn:SAMA2:klg-e7947cc0-8392-4dac-8e5f-5ff96fe8cd24"},"Meta":{"MultipleAuthorizers":{"TotalRequired":0,"Authorizations":[{"AuthorizerId":0,"AuthorizerName":0,"AuthorizerType":"Financial","AuthorizationDate":"2022-12-07T09:50:06.252Z","AuthorizationStatus":"Pending"}]}}}}`
