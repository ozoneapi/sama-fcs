package generation

import (
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/schema"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/spec"
	"github.com/sirupsen/logrus"

	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/discovery"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/model"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/names"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/permissions"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/testlist"
)

// APIRun represents all apis and their test and a list of tokens
// required to run those tests
type APIRun struct {
	APITests           []APITests                   `json:"specCases"`
	ConsentPermissions []model.ConsentURLPermission `json:"specTokens"`
}

// APITests - test cases generated for a specification
type APITests struct {
	APISpec   discovery.APISpecification `json:"apiSpecification"`
	TestCases []model.TestCase           `json:"testCases"`
}

// GeneratorConfig -
type GeneratorConfig struct {
	ClientID              string
	Aud                   string
	ResponseType          string
	Scope                 string
	AuthorizationEndpoint string
	RedirectURL           string
	ResourceIDs           model.ResourceIDs
}

// Generator - generates test cases from discovery model
type Generator interface {
	GenerateTests(config GeneratorConfig, apiCollection discovery.APICollection,
		ctx *model.Context, conditional []discovery.ConditionalAPIProperties, log *logrus.Entry) (APIRun, testlist.TestDefinitions, map[spec.Type][]testlist.RequiredTokens)
}

// NewGenerator - returns implementation of Generator interface
func NewGenerator() Generator {
	return generator{
		resolver: permissions.Resolver,
	}
}

// generator - implements Generator interface
type generator struct {
	resolver func(groups []permissions.Group) permissions.PermissionTestCollection
}

// Work in progress to integrate Manifest Test
func (g generator) GenerateTests(config GeneratorConfig,
	apiCollection discovery.APICollection,
	ctx *model.Context,
	conditionalProperties []discovery.ConditionalAPIProperties,
	log *logrus.Entry) (APIRun, testlist.TestDefinitions, map[spec.Type][]testlist.RequiredTokens) {

	log = log.WithField("module", "GenerateTests")

	for k, item := range apiCollection.APIDefinitions { // For each spec defined in the discovery file
		spectype, err := spec.GetSpecType(item.APISpecification.Name) // arbitary uinque identifier per spec
		if err != nil {
			logrus.Warnf("Cannot get spec type Spec Name: " + item.APISpecification.Name)
			log.Warnf("specification %s not found", item.APISpecification.Name)
			continue
		}

		log.Debugf("Generating testcases for %s API", spectype)
		apiCollection.APIDefinitions[k].APISpecification.SpecType = spectype // update the spec type with what we've found
		ctx.PutString(spectype.BaseURLID(), item.ResourceBaseURI)            // Allow the baseurl used for the spec to be stored
	}

	specTestCases := []APITests{}
	scrSlice := []model.ConsentURLPermission{}
	var filteredScripts testlist.TestDefinitions
	tokens := map[spec.Type][]testlist.RequiredTokens{}
	// Collect All Tests for All specs  in discovery file
	for _, item := range apiCollection.APIDefinitions { // For each Spec defined in the discovery file
		specType, specVersion, err := spec.GetVersionType(item.APISpecification.Name, item.APISpecification.Version)
		if err != nil {
			log.WithError(err).Warnf("Get Version, Spec failed for  %s %s :"+err.Error(), item.APISpecification.SchemaVersion, item.APISpecification.Version)
		}
		validator, err := schema.NewOpenAPI3Validator(specType, specVersion) // configure an OpenApi3 validator,
		if err != nil {
			log.WithError(err).Warnf("cannot create Schema Validator for %s %s", item.APISpecification.Name, item.APISpecification.Version)
			validator = schema.NewNullValidator()
		}
		log.WithFields(logrus.Fields{"name": item.APISpecification.Name, "version": item.APISpecification.Version}).
			Info("swagger spec validator created")

		params := testlist.GenerationParameters{
			//	Scripts:      scripts,
			Spec:        item.APISpecification,
			Baseurl:     item.ResourceBaseURI,
			Ctx:         ctx,
			Endpoints:   item.Endpoints,
			Validator:   validator,
			Conditional: conditionalProperties,
			TestPath:    item.Tests,
		}

		// Generate Test Cases
		// and Filtered Test Cases
		tcs, fsc, err := testlist.GenerateTestCases(&params)

		filteredScripts = fsc
		if err != nil {
			log.Warnf("Generate Tests failed for %s", item.APISpecification.SchemaVersion)
			continue
		}

		spectype := item.APISpecification.SpecType
		requiredSpecTokens, err := testlist.GetRequiredTokensFromTests(tcs, spectype)
		if err != nil {
			log.Warnf("failed to retrieve required spec tokens from test for spec %s", spectype)
			continue
		}
		logrus.Debugf("%s required spec tokens: %+v", spectype, requiredSpecTokens)
		specreq, err := getSpecConsentsFromRequiredTokens(requiredSpecTokens, item.APISpecification.Name)
		if err != nil {
			log.Warnf("failed to retrieve spec consents from required spec tokens for spec %s", spectype)
			continue
		}
		scrSlice = append(scrSlice, specreq)
		// @NEW-SPEC-RELEASE - make sure any new typew is handled properly
		if spectype == "payments" || spectype == "cbpii" || spectype == "vrps" {
			// three sets of test case. all, UI, consent (Non-ui)
			// split tests between one's that should be shown in the GUI and supporting ones (some consents) that shouldn't
			tcs = getUITests(tcs)
		}

		stc := APITests{APISpec: item.APISpecification, TestCases: tcs}
		logrus.Debugf("%d test cases generated for %s", len(tcs), item.APISpecification.Name)
		specTestCases = append(specTestCases, stc)
		tokens[spectype] = requiredSpecTokens
	}

	for _, item := range scrSlice {
		logrus.Tracef("%#v", item)
	}
	for _, v := range tokens {
		logrus.Tracef("%#v", v)
	}
	return APIRun{specTestCases, scrSlice}, filteredScripts, tokens
}

// taks all the payment testscases
// returns two sets
// set 1) - payment tests that show in the UI and execution when runtests is called
// set 2) - payment consent tests that need to be authorised before runtests can happen
func getUITests(tcs []model.TestCase) []model.TestCase {

	uiTests := []model.TestCase{}
	consentJobs := testlist.GetConsentJobs()

	for _, test := range tcs {
		_, exists := consentJobs.Get(test.ID)
		if exists {
			logrus.Tracef("skipping job %s", test.ID)
			continue
		}
		uiTests = append(uiTests, test)
	}

	return uiTests
}

// Packages up Required tokens into a SpecConsentRequirements structure
func getSpecConsentsFromRequiredTokens(rt []testlist.RequiredTokens, apiName string) (model.ConsentURLPermission, error) {
	npa := []model.NamedPermission{}
	for _, v := range rt {
		np := model.NamedPermission{}
		np.Name = v.Name
		np.PermissionSetTestCases = permissions.PermissionSetTestCases{}
		np.PermissionSetTestCases.TestCaseIDs = append(np.PermissionSetTestCases.TestCaseIDs, permissions.StringSliceToTestID(v.IDs)...)
		np.PermissionSetTestCases.PermissionSet = append(np.PermissionSetTestCases.PermissionSet, permissions.StringSliceToPermissionSet(v.Perms)...)
		npa = append(npa, np)
	}
	specConsentReq := model.ConsentURLPermission{Identifier: apiName, NamedPermissions: npa}
	return specConsentReq, nil
}

// consentRequirements calls resolver to get list of permission sets required to run all test cases
func (g generator) consentRequirements(specTestCases []APITests) []model.ConsentURLPermission {
	nameGenerator := names.NewSequentialPrefixedName("to")
	specConsentRequirements := []model.ConsentURLPermission{}
	for _, spec := range specTestCases {
		var groups []permissions.Group
		for _, tc := range spec.TestCases {
			g := model.NewDefaultPermissionGroup(tc)
			groups = append(groups, g)
		}
		resultSet := g.resolver(groups)
		consentRequirements := model.NewSpecConsentRequirements(nameGenerator, resultSet, spec.APISpec.Name)
		specConsentRequirements = append(specConsentRequirements, consentRequirements)
	}
	return specConsentRequirements
}
