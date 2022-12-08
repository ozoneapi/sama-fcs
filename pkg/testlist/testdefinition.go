package testlist

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/schema"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/spec"
	"bitbucket.org/ozoneapi/sama-conformance-suite/resources"
	"github.com/blang/semver/v4"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/sjson"

	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/discovery"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/model"
)

/*
	TestDefinitions are the high level test case definitions.
	These definitions are translated into model.TestCases which have the
	detail of exactly what needs to be done.

	The idea is that test definitions are a simpler higher level abstraction.
*/

// TestDefinitions -
type TestDefinitions struct {
	TestDefinitions []TestDefinition `json:"scripts,omitempty"`
}

// TestDefinition represents a highlevel test definition
type TestDefinition struct {
	APIName               string            `json:"apiName,omitempty"`
	APIVersion            string            `json:"apiVersion,omitempty"`
	Description           string            `json:"description,omitempty"`
	Detail                string            `json:"detail,omitempty"`
	ID                    string            `json:"id,omitempty"`
	RefURI                string            `json:"refURI,omitempty"`
	Parameters            map[string]string `json:"parameters,omitempty"`
	QueryParameters       map[string]string `json:"queryParameters,omitempty"`
	Headers               map[string]string `json:"headers,omitempty"`
	RemoveHeaders         []string          `json:"removeHeaders,omitempty"`
	RemoveSignatureClaims []string          `json:"removeSignatureClaims,omitempty"`
	Body                  string            `json:"body,omitempty"`
	Permissions           []string          `json:"permissions,omitemtpy"`
	PermissionsExcluded   []string          `json:"permissions-excluded,omitemtpy"`
	Resource              string            `json:"resource,omitempty"`
	Asserts               []string          `json:"asserts,omitempty"`
	AssertsOneOf          []string          `json:"asserts_one_of,omitempty"`
	Method                string            `json:"method,omitempty"`
	URI                   string            `json:"uri,omitempty"`
	URIImplemenation      string            `json:"uriImplementation,omitempty"`
	SchemaCheck           string            `json:"schemaCheck,omitempty"`
	ContextPut            map[string]string `json:"saveToContext,omitempty"`
	UseCCGToken           string            `json:"useCCGToken,omitempty"`
	ValidateSignature     string            `json:"validateSignature,omitempty"`
	ParentID              string            `json:"parent,omitempty"`
	Claims                map[string]string `json:"claims,omitempty"`
	ContentType           string            `json:"contentType,omitempty"`
}

// GetByID - finds a testDefinition ID in a list of high level tests and returns it
func (tds *TestDefinitions) GetByID(idToFind string) *TestDefinition {
	for _, v := range tds.TestDefinitions {
		if v.ID == idToFind {
			return &v
		}
	}
	return nil
}

// InheritFrom -
// Merge a parents values
func (t *TestDefinition) InheritFrom(parent *TestDefinition) {
	t.Parameters = MergeParentChild(parent.Parameters, t.Parameters)
	t.QueryParameters = MergeParentChild(parent.QueryParameters, t.QueryParameters)
	t.Headers = MergeParentChild(parent.Headers, t.Headers)
	t.ContextPut = MergeParentChild(parent.ContextPut, t.ContextPut)
	t.Claims = MergeParentChild(parent.Claims, t.Claims)

	t.RemoveHeaders = MergeStringSlice(parent.RemoveHeaders, t.RemoveHeaders)
	t.RemoveSignatureClaims = MergeStringSlice(parent.RemoveSignatureClaims, t.RemoveSignatureClaims)
	t.Permissions = MergeStringSlice(parent.Permissions, t.Permissions)
	t.PermissionsExcluded = MergeStringSlice(parent.PermissionsExcluded, t.PermissionsExcluded)
	t.Asserts = MergeStringSlice(parent.Asserts, t.Asserts)
	t.AssertsOneOf = MergeStringSlice(parent.AssertsOneOf, t.AssertsOneOf)

	t.APIName = ReplaceIfEmpty(parent.APIName, t.APIName)
	t.APIVersion = ReplaceIfEmpty(parent.APIVersion, t.APIVersion)
	t.Body = ReplaceIfEmpty(parent.Body, t.Body)
	t.Resource = ReplaceIfEmpty(parent.Resource, t.Resource)
	t.Method = ReplaceIfEmpty(parent.Method, t.Method)
	t.URI = ReplaceIfEmpty(parent.URI, t.URI)
	t.URIImplemenation = ReplaceIfEmpty(parent.URIImplemenation, t.URIImplemenation)
	t.SchemaCheck = ReplaceIfEmpty(parent.SchemaCheck, t.SchemaCheck)
	t.UseCCGToken = ReplaceIfEmpty(parent.UseCCGToken, t.UseCCGToken)
	t.ValidateSignature = ReplaceIfEmpty(parent.ValidateSignature, t.ValidateSignature)
	t.ContentType = ReplaceIfEmpty(parent.ContentType, t.ContentType)
}

// ResolveInheritedDefinitions - need moving into testlist package ...
func ResolveInheritedDefinitions(src TestDefinitions) (TestDefinitions, error) {
	td := TestDefinitions{}

	baseTests := TestDefinitions{}
	inheritedTests := TestDefinitions{}

	// Split out tests with and without parents - inherited and base tests
	for _, v := range src.TestDefinitions {
		if !v.HasParent() {
			baseTests.TestDefinitions = append(baseTests.TestDefinitions, v)
		} else {
			inheritedTests.TestDefinitions = append(inheritedTests.TestDefinitions, v)
		}
	}

	for k, v := range inheritedTests.TestDefinitions {
		parent := baseTests.GetByID(v.ParentID)
		if parent == nil {
			// look for parentId in tests with parents
			parent = inheritedTests.GetByID(v.ParentID)
			if parent == nil {
				// return error -- cannot find it anywhere
				return td, fmt.Errorf("test %s, cannot find parentId %s for inheritance", v.ID, v.ParentID)
			}
		}
		v.InheritFrom(parent)                 // update
		inheritedTests.TestDefinitions[k] = v // put back
	}

	for _, v := range baseTests.TestDefinitions {
		td.TestDefinitions = append(td.TestDefinitions, v)
	}
	for _, v := range inheritedTests.TestDefinitions {
		td.TestDefinitions = append(td.TestDefinitions, v)
	}

	sortList = td.TestDefinitions
	sort.Slice(sortList, compareTestDefs)
	td.TestDefinitions = sortList
	return td, nil
}

var sortList []TestDefinition

func compareTestDefs(i, j int) bool {
	return sortList[i].ID < sortList[j].ID
}

// ReplaceIfEmpty -
func ReplaceIfEmpty(parent, child string) string {
	if len(child) > 0 {
		return child
	}
	return parent
}

// MergeParentChild -
func MergeParentChild(parent, child map[string]string) map[string]string {
	result := map[string]string{}
	for k, v := range parent { // put the first set of k,v in new map
		result[k] = v
	}
	for k, v := range child { // add second set over the top replacing any previous keys
		result[k] = v
	}
	return result
}

// MergeStringSlice -
func MergeStringSlice(str1, str2 []string) []string {
	strtmp := []string{}
	for _, v := range str1 {
		strtmp = append(strtmp, v)
	}
	for _, v := range str2 {
		strtmp = append(strtmp, v)
	}
	result := deDupString(strtmp)

	return result
}

func deDupString(stringSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}

	for _, entry := range stringSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// HasParent - to inherit from
func (t *TestDefinition) HasParent() bool {
	if len(t.ParentID) > 0 {
		return true
	}
	return false
}

func copyStringMap(original map[string]string) map[string]string {
	target := make(map[string]string)

	for key, value := range original {
		target[key] = value
	}
	return target
}

// References - reference collection
type References struct {
	References map[string]Reference `json:"references,omitempty"`
}

// Reference is an item referred to by the test script list an assert of token reqirement
type Reference struct {
	Expect      model.Expect `json:"expect,omitempty"`
	Permissions []string     `json:"permissions,omitempty"`
	Body        interface{}  `json:"body,omitempty"`
	BodyData    string       `json:"bodyData"`
}

// ConsentJobs Holds jobs required only to provide consent so should not show on the ui
type ConsentJobs struct {
	jobs map[string]model.TestCase
}

var cj *ConsentJobs

// GetConsentJobs - makes a structure to hold a list of payment consent jobs than need to be run before the main tests
// and so aren't included in the main test list
func GetConsentJobs() *ConsentJobs {
	if cj == nil {
		jobs := make(map[string]model.TestCase)
		cj = &ConsentJobs{jobs: jobs}
		return cj
	}
	return cj
}

// Add a consent Job
func (cj *ConsentJobs) Add(tc model.TestCase) {
	cj.jobs[tc.ID] = tc
}

// Get a consentJob
func (cj *ConsentJobs) Get(testid string) (model.TestCase, bool) {
	value, exist := cj.jobs[testid]
	return value, exist
}

// GenerationParameters -
type GenerationParameters struct {
	TestDefinitions TestDefinitions
	Spec            discovery.APISpecification
	Baseurl         string
	Ctx             *model.Context
	Endpoints       []discovery.Endpoint
	Validator       schema.Validator
	Conditional     []discovery.ConditionalAPIProperties
	TestPath        string
}

// GenerateTests - simplified version!!!! - not used by DISCOVERY JOURNEY
func GenerateTests(tds TestDefinitions, refs *References, parentSession *model.Context,
	baseURL string, spectype spec.Type, validator schema.Validator,
	apiSpec discovery.APISpecification) ([]model.TestCase, error) {

	tests := []model.TestCase{}

	// Resolve any test inheritence
	testDefinitions, err := ResolveInheritedDefinitions(tds)
	if err != nil {
		log.WithError(err).Error("Resolving Inherited Definitions")
	}

	for _, testDefinition := range testDefinitions.TestDefinitions {
		localCtx, err := testDefinition.ProcessParameters(refs, parentSession)
		if err != nil {
			log.WithError(err).Error("Error on processParameters")
			return nil, err
		}

		interactionID := uuid.New().String()
		tc, err := buildTestCase(testDefinition, refs.References, localCtx, baseURL, spectype, validator, apiSpec, interactionID)
		if err != nil {
			log.WithError(err).Error("Error on testCaseBuilder")
			return nil, err
		}

		localCtx.PutContext(parentSession)

		showReplacementErrors := true
		tc.ProcessReplacementFields(localCtx, showReplacementErrors)

		// TODO --- Add this back ...
		// err = AddConditionalPropertiesToRequest(&tc, ) // Add Conditional Properties to the request
		// if err != nil {
		// 	return nil, TestDefinitions{}, err
		// }

		AddQueryParametersToRequest(&tc, testDefinition.QueryParameters)
		tests = append(tests, tc)
	}

	return tests, nil
}

// GenerateTestCases examines a manifest file, asserts file and resources definition, then builds the associated test cases
func GenerateTestCases(params *GenerationParameters) ([]model.TestCase, TestDefinitions, error) {
	v := semver.Version{}
	specType, v, err := spec.GetVersionType(params.Spec.Name, params.Spec.Version)
	if err != nil {
		return nil, TestDefinitions{}, errors.New("unknown specification " + params.Spec.SchemaVersion)
	}
	var testDefinitionsPath string
	if len(params.TestPath) > 0 {
		testDefinitionsPath = params.TestPath
	} else {
		testDefinitionsPath, err = spec.GetTestDefinitionsPath(specType)
		if err != nil {
			return nil, TestDefinitions{}, errors.New("cannot get manifest path from spectype: " + specType.String() + " " + err.Error())
		}
	}
	log.Infof("testDefinitionPath set to %s", testDefinitionsPath)

	log.Info("GenerateTestCases for spec type:" + specType.String())
	// All tests for a specifi spec are loaded here.
	testDefinitions, refs, err := LoadReferenceData(specType, v, testDefinitionsPath)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Error("Error on loadGenerationResources")
		return nil, TestDefinitions{}, err
	}

	// Resolve any test inheritence
	testDefinitions, err = ResolveInheritedDefinitions(testDefinitions)
	if err != nil {
		log.WithError(err).Error("Resolving Inherited Definitions")
	}

	filteredTests, err := FilterTestsBasedOnDiscoveryEndpoints(testDefinitions, params.Endpoints, specType)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("error filter scripts based " + specType.String() + "discovery")
	}

	tests := []model.TestCase{}

	for _, testDefinition := range filteredTests.TestDefinitions {
		localCtx, err := testDefinition.ProcessParameters(&refs, params.Ctx)
		if err != nil {
			log.WithError(err).Error("Error on processParameters")
			return nil, TestDefinitions{}, err
		}

		interactionID := uuid.New().String()
		tc, err := buildTestCase(testDefinition, refs.References, localCtx, params.Baseurl, specType, params.Validator, params.Spec, interactionID)
		if err != nil {
			log.WithError(err).Error("Error on testCaseBuilder")
		}

		localCtx.PutContext(params.Ctx)
		showReplacementErrors := true
		tc.ProcessReplacementFields(localCtx, showReplacementErrors)

		err = AddConditionalPropertiesToRequest(&tc, params.Conditional)
		if err != nil {
			return nil, TestDefinitions{}, err
		}

		AddQueryParametersToRequest(&tc, testDefinition.QueryParameters)
		tests = append(tests, tc)
	}

	return tests, filteredTests, nil
}

// AddQueryParametersToRequest -
func AddQueryParametersToRequest(tc *model.TestCase, parameters map[string]string) {
	for k, v := range parameters {
		// FormData is encoded to URL query parameters on "GET" requests
		tc.Input.QueryParameters[k] = v
	}
}

// AddConditionalPropertiesToRequest -
func AddConditionalPropertiesToRequest(tc *model.TestCase, conditional []discovery.ConditionalAPIProperties) error {
	for _, cond := range conditional {
		for _, ep := range cond.Endpoints {
			if tc.Input.Method == ep.Method && tc.Input.Endpoint == ep.Path {
				// try to add property to body request
				for _, prop := range ep.ConditionalProperties {
					isRequestProperty, propertyType, err := tc.Validator.IsRequestProperty(tc.Input.Method, tc.Input.Endpoint, prop.Path)
					if err != nil {
						log.Error(err)
						return err
					}
					if isRequestProperty && len(prop.Value) > 0 {
						var err error
						if propertyType == "[array]" {
							stringArray := convertInputStringToArray(prop.Value)
							tc.Input.RequestBody, err = sjson.Set(tc.Input.RequestBody, prop.Path, stringArray)
						} else if propertyType == "[object]" && prop.Schema == "OBSupplementaryData1" { // handle freeform supplementary data into request payload
							path := prop.Path + "." + prop.Name
							tc.Input.RequestBody, err = sjson.Set(tc.Input.RequestBody, path, prop.Value)
						} else {
							tc.Input.RequestBody, err = sjson.Set(tc.Input.RequestBody, prop.Path, prop.Value)
						}
						if err != nil {
							log.Error(err)
							return err
						}
					}
				}
			}
		}
	}

	return nil
}

func convertInputStringToArray(value string) []string {
	return strings.Split(value, ",")
}

var fnReplacementRegex = regexp.MustCompile(`[^\$fn:]?\$fn:([\w|_]*)\(([\w,\s-,:,\.]*)\)`)

// ProcessParameters -
// Process the parameter section of the script definition
func (t *TestDefinition) ProcessParameters(refs *References, resources *model.Context) (*model.Context, error) {
	localCtx := model.Context{}

	for k, value := range t.Parameters {
		contextValue := value
		if k == "consentId" {
			localCtx.PutString("consentId", value)
			continue
		}

		if isFunction(value) {
			fnName, fnArgs, err := fnNameAndArgs(value)
			if err != nil {
				return nil, err
			}
			result, err := model.ExecuteMacro(fnName, fnArgs)
			if err != nil {
				logrus.Debugf("error executing function '%s' with parameters %s : %v", fnName, fnArgs, err)
				return nil, err
			}
			localCtx.PutString(k, result)
			continue
		}

		if strings.Contains(value, "$") {
			str := value[1:]
			//lookup parameter in resources - accountids
			value, _ = resources.GetString(str)
			//lookup parameter in reference data
			ref := refs.References[str]
			val := ref.getValue()
			if len(val) != 0 {
				contextValue = val
			}
			if len(value) == 0 {
				value, _ = localCtx.GetString(str)
				if len(value) == 0 {
					localCtx.PutString(k, contextValue)
					continue
				}
			}
		}
		switch k {
		case "tokenRequestScope":
			localCtx.PutString("tokenScope", value)
		default:
			localCtx.PutString(k, value)
		}
	}
	if len(t.Permissions) > 0 {
		localCtx.PutStringSlice("permissions", t.Permissions)
	}
	if len(t.PermissionsExcluded) > 0 {
		localCtx.PutStringSlice("permissions-excluded", t.PermissionsExcluded)
	}
	return &localCtx, nil
}

func isFunction(param string) bool {
	return strings.HasPrefix(param, "$fn:")
}

func fnNameAndArgs(param string) (string, []string, error) {
	fnNameAndArgs := fnReplacementRegex.FindStringSubmatch(param)
	if fnNameAndArgs == nil {
		return "", nil, errors.New("function name format error processing " + param)
	}
	fnArgs := []string{}
	// fn has some parameters
	if len(fnNameAndArgs) > 2 && fnNameAndArgs[2] != "" {
		fnArgs = strings.Split(fnNameAndArgs[2], ",")
	}

	return fnNameAndArgs[1], fnArgs, nil
}

func (r *Reference) getValue() string {
	return r.BodyData
}

// sets testCase Bearer Header to match requested consent token - for non-consent tests
func updateTestAuthenticationFromToken(tcs []model.TestCase, rts []RequiredTokens) []model.TestCase {
	for _, rt := range rts {
		for x, tc := range tcs {
			for _, id := range rt.IDs {
				if id == tc.ID {
					reqConsent, err := tc.Context.GetString("requestConsent")
					if err == nil && len(reqConsent) > 0 {
						continue
					}

					tc.InjectBearerToken("$" + rt.Name)
					tcs[x] = tc
				}
			}
		}
	}
	return tcs
}

// BuildTestCase - script build function - ready for
func (t *TestDefinition) BuildTestCase(refs map[string]Reference, ctx *model.Context, baseurl string, specType spec.Type, validator schema.Validator, apiSpec discovery.APISpecification, interactionID string) (model.TestCase, error) {
	return buildTestCase(*t, refs, ctx, baseurl, specType, validator, apiSpec, interactionID)
}

func buildTestCase(s TestDefinition, refs map[string]Reference, ctx *model.Context, baseurl string, specType spec.Type, validator schema.Validator, apiSpec discovery.APISpecification, interactionID string) (model.TestCase, error) {
	tc := model.MakeTestCase()
	tc.ID = s.ID
	tc.Name = s.Detail
	tc.Detail = s.Detail
	tc.RefURI = s.RefURI
	tc.APIName = apiSpec.Name
	tc.APIVersion = apiSpec.Version
	tc.Validator = validator
	if s.ValidateSignature == "true" {
		tc.ValidateSignature = true
	}

	//TODO: make these more configurable - header also get set in buildInput Section
	tc.Input.Headers["x-fapi-financial-id"] = "$x-fapi-financial-id"
	// TODO: use automated interaction-id generation - one id per run - injected into context at journey
	tc.Input.Headers["x-fapi-interaction-id"] = interactionID
	tc.Input.Headers["x-fcs-testcase-id"] = tc.ID
	tc.Input.Headers["x-fapi-customer-ip-address"] = "$x-fapi-customer-ip-address"
	buildInputSection(s, &tc.Input)

	if len(s.ContentType) > 0 { // override any contenttype headers if test definition contenttype is set explicitly
		tc.Input.SetContentTypeHeader(s.ContentType)
	}

	tc.Purpose = s.Detail
	tc.Context = model.Context{}

	tc.Context.PutContext(ctx)
	tc.Context.PutString("x-fapi-financial-id", "$x-fapi-financial-id")
	tc.Context.PutString("baseurl", baseurl)
	if s.UseCCGToken == "true" {
		tc.Context.PutString("useCCGToken", "yes") // used for payment posts
	}

	for _, a := range s.Asserts {
		ref, exists := refs[a]
		if !exists {
			msg := fmt.Sprintf("assertion %s do not exist in reference data", a)
			logrus.Error(msg)
			return tc, errors.New(msg)
		}
		clone := ref.Expect.Clone()
		if ref.Expect.StatusCode != 0 {
			tc.Expect.StatusCode = clone.StatusCode
		}
		tc.Expect.Matches = append(tc.Expect.Matches, clone.Matches...)
	}

	for _, a := range s.AssertsOneOf {
		ref, exists := refs[a]
		if !exists {
			msg := fmt.Sprintf("assertion %s do not exist in reference data", a)
			logrus.Error(msg)
			return tc, errors.New(msg)
		}
		tc.ExpectOneOf = append(tc.ExpectOneOf, ref.Expect.Clone())
	}

	if s.SchemaCheck == "true" {
		tc.Expect.SchemaValidation = true
	} else {
		tc.Expect.SchemaValidation = false // state explicitly
	}

	// Handled PutContext parameters
	putMatches := processPutContext(&s)
	if len(putMatches) > 0 {
		tc.Expect.ContextPut.Matches = putMatches
	}

	ctx.PutContext(&tc.Context)
	tc.ProcessReplacementFields(ctx, false)
	_, exists := tc.Context.GetString("postData")
	if exists == nil {
		tc.Context.Delete("postData") // tidy context as bodydata potentially large
	}

	if specType == spec.ObiePayment && tc.Input.Method == "POST" {
		tc.Input.JwsSig = true
		tc.Input.IdempotencyKey = true
	}
	if specType == spec.ObieVRP && tc.Input.Method == "POST" {
		tc.Input.JwsSig = true
		if strings.Contains(tc.Input.Method, "funds-confirmation") {
			tc.Input.IdempotencyKey = false
		} else {
			tc.Input.IdempotencyKey = true
		}
	}

	return tc, nil
}

func processPutContext(s *TestDefinition) []model.Match {
	m := []model.Match{}
	name, exists := s.ContextPut["name"]
	if !exists {
		return m
	}
	value, exists := s.ContextPut["value"]
	if !exists {
		return m
	}
	mx := model.Match{ContextName: name, JSON: value}
	m = append(m, mx)
	return m
}

func buildInputSection(s TestDefinition, i *model.Input) {
	i.Method = strings.ToUpper(s.Method)
	i.Endpoint = s.URI
	for k, v := range s.Headers {
		i.Headers[k] = v
	}

	i.RemoveHeaders = make([]string, 0, len(s.RemoveHeaders))
	for _, header := range s.RemoveHeaders {
		i.RemoveHeaders = append(i.RemoveHeaders, header)
	}

	i.RemoveClaims = make([]string, 0, len(s.RemoveSignatureClaims))
	for _, claim := range s.RemoveSignatureClaims {
		i.RemoveClaims = append(i.RemoveClaims, claim)
	}

	for k, v := range s.Claims {
		i.Claims[k] = v
	}

	i.RequestBody = s.Body
}

// GetReferenceData -
// get Assertions and Body Templates
func GetReferenceData(specType spec.Type) (References, error) {
	return loadAssertions(specType)
}

// GetTestsForSpec -
func GetTestsForSpec(specType spec.Type) (TestDefinitions, error) {
	testDefinitionPath, err := spec.GetTestDefinitionsPath(specType)
	if err != nil {
		return TestDefinitions{}, err
	}
	scripts, err := loadScripts(testDefinitionPath)
	if err != nil {
		return TestDefinitions{}, err
	}
	return scripts, nil
}

// LoadReferenceData -
// Load file resources required to perform the testcase generation
func LoadReferenceData(specType spec.Type, specVersion semver.Version, testPath string) (TestDefinitions, References, error) {
	var err error

	assertions, err := loadAssertions(specType)
	if err != nil {
		return TestDefinitions{}, References{}, err
	}
	testDefinitions, err := loadScripts(testPath)
	if err != nil {
		return TestDefinitions{}, References{}, err
	}

	sc, err := FilterTestDefinitionsByVersion(specVersion, testDefinitions)
	if err != nil {
		return TestDefinitions{}, References{}, err
	}

	return sc, assertions, err

}

// FilterTestDefinitionsByVersion -  scripts by version
func FilterTestDefinitionsByVersion(specVersion semver.Version, scAllScripts TestDefinitions) (TestDefinitions, error) {
	td := TestDefinitions{}
	allVersions, _ := semver.Make("0.0.0")
	for _, currentScript := range scAllScripts.TestDefinitions {
		if currentScript.APIVersion == "" {
			td.TestDefinitions = append(td.TestDefinitions, currentScript)
		} else {
			if allVersions.Compare(specVersion) == 0 {
				td.TestDefinitions = append(td.TestDefinitions, currentScript)
				continue
			}
			testRange, err := semver.ParseRange(currentScript.APIVersion)
			if err != nil {
				return TestDefinitions{}, err
			}
			if testRange(specVersion) {
				td.TestDefinitions = append(td.TestDefinitions, currentScript)
			}
		}
	}
	return td, nil
}

func getSpecVersion(spectype spec.Type, apiVersions []string) (semver.Version, error) {
	for _, v := range apiVersions {
		api := strings.Split(v, "_v")
		if len(api) > 1 {
			if strings.Compare(spectype.String(), api[0]) == 0 {
				s1, err := semver.Make(api[1])
				if err != nil {
					return s1, err
				}
				return s1, nil
			}
		}
	}

	return semver.Version{}, fmt.Errorf("getSpecVersion: cannot parse versions %v", apiVersions)
}

func loadAssertions(specType spec.Type) (References, error) {

	assertionFile := "assertions.json"

	if specType == spec.KsaAccount || specType == spec.KsaLetter {
		// KSA Specific error codes
		assertionFile = "ksa_assertions.json"
	}

	refs, err := loadReferences(assertionFile)
	if err != nil {
		return References{}, err
	}

	refs2, err := loadReferences("data.json")
	if err != nil {
		return References{}, err
	}

	for k, v := range refs2.References { // read in data references with body payloads
		body := jsonString(v.Body)
		l := len(body)
		if l > 0 {
			v.BodyData = body
			v.Body = ""
			refs2.References[k] = v
		}
		refs.References[k] = refs2.References[k]
	}

	return refs, err
}

func jsonString(i interface{}) string {
	var model []byte
	model, _ = json.MarshalIndent(i, "", "    ")
	return string(model)
}

func loadScripts(filename string) (TestDefinitions, error) {
	url, err := url.Parse(filename)
	if err != nil {
		return TestDefinitions{}, errors.New("loadscripts: unsupported test definition " + filename)
	}

	file := "testdefs" + url.Path
	bytes, err := resources.Testdefs.ReadFile(file)
	if err != nil {
		return TestDefinitions{}, errors.New("loadscripts: unable to open testdefintion  " + filename)
	}

	td := TestDefinitions{}
	err = json.Unmarshal(bytes, &td)
	if err != nil {
		return TestDefinitions{}, err
	}
	return td, nil
}

func loadReferences(filename string) (References, error) {
	targetFile := "testdefs/" + filename
	bytes, err := resources.Testdefs.ReadFile(targetFile)
	if err != nil {
		return References{}, err
	}
	var m References
	err = json.Unmarshal(bytes, &m)
	if err != nil {
		return References{}, err
	}
	return m, nil
}

// ScriptPermission -
type ScriptPermission struct {
	ID          string
	Permissions []string
	Path        string
}

// GetPermissions -
func getAccountPermissions(tests []model.TestCase) []ScriptPermission {
	permCollector := []ScriptPermission{}

	for _, test := range tests {
		ctx := test.Context
		perms, err := ctx.GetStringSlice("permissions")
		if err != nil {
			continue
		}

		sp := ScriptPermission{ID: test.ID, Permissions: perms, Path: test.Input.Method + " " + test.Input.Endpoint}
		permCollector = append(permCollector, sp)
	}

	return permCollector
}

// FilterTestsBasedOnDiscoveryEndpoints returns a subset of the first `scripts` parameter, thus filtering `scripts`.
// Filtering is performed by matching (via `regPaths` regex's) the provided `endpoints` against the provided `scripts`.
// The result is: For each path in the collection of scripts returned, there is at least one matching path in the `endpoint`
// list.
// ---
func FilterTestsBasedOnDiscoveryEndpoints(specTests TestDefinitions, endpoints []discovery.Endpoint, specType spec.Type) (TestDefinitions, error) {

	regPaths := getEndpointsRegexForSpec(specType)
	if len(regPaths) == 0 {
		return specTests, nil // return what was input unchanged
	}

	// Match paths in predefined regex for each spec to perform filtering
	var filteredTestDefinitions []TestDefinition
	lookupMap := make(map[string]bool)
	for _, ep := range endpoints {
		for _, regPath := range regPaths {
			matched, err := regexp.MatchString(regPath.Regex, ep.Path)
			if err != nil {
				continue
			}
			if matched {
				lookupMap[regPath.Regex] = true
			}
		}
	}

	for k := range lookupMap {
		for _, scr := range specTests.TestDefinitions {
			stripped := strings.Replace(scr.URI, "$", "", -1) // only works with a single character
			if strings.Contains(stripped, "foobar") {         //exceptions - as its not in the list of supported
				//endpoints but we cant it included ... as a -ve test
				noFoobar := strings.Replace(stripped, "/foobar", "", -1) // only works with a single character
				matched, err := regexp.MatchString(k, noFoobar)
				if err != nil {
					continue
				}
				if matched {
					if !contains(filteredTestDefinitions, scr) {
						filteredTestDefinitions = append(filteredTestDefinitions, scr)
					}
				}

				if scr.URI == "/foobar" {
					if !contains(filteredTestDefinitions, scr) {
						filteredTestDefinitions = append(filteredTestDefinitions, scr)
					}
					continue
				}
			}

			matched, err := regexp.MatchString(k, stripped)
			if err != nil {
				continue
			}
			if matched {
				if !contains(filteredTestDefinitions, scr) {
					filteredTestDefinitions = append(filteredTestDefinitions, scr)
				}
			}
		}
	}
	result := TestDefinitions{TestDefinitions: filteredTestDefinitions}
	sort.Slice(result.TestDefinitions, func(i, j int) bool { return result.TestDefinitions[i].ID < result.TestDefinitions[j].ID })

	return result, nil
}
