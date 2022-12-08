package schema

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/spec"
	"bitbucket.org/ozoneapi/sama-conformance-suite/resources"
	"github.com/blang/semver/v4"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	legacyrouter "github.com/getkin/kin-openapi/routers/legacy"
	"github.com/pkg/errors"
)

// HTTPResponse represents a response object from a HTTP Call
type HTTPResponse struct {
	Method     string
	Path       string
	Header     http.Header
	Body       io.Reader
	StatusCode int
}

// Failure represents a validation failure
type Failure struct {
	Message string
}

func newFailure(message string) Failure {
	return Failure{
		Message: message,
	}
}

// Validator validates a HTTP response object against a schema
type Validator interface {
	Validate(HTTPResponse) ([]Failure, error)
	IsRequestProperty(method, path, propertpath string) (bool, string, error)
}

// OpenAPI3Validator - type
type OpenAPI3Validator struct {
	router routers.Router
	doc    *openapi3.T
}

// RequestWrapper -
type RequestWrapper struct {
	Method      string
	URL         string
	ContentType string
	Body        string
}

// ResponseWrapper -
type ResponseWrapper struct {
	Status      int
	ContentType string
	Body        string
}

// internal validation parameters
type validateParams struct {
	httpReq    *http.Request
	route      *routers.Route
	pathParams map[string]string
	statusCode int
	header     http.Header
	body       []byte
}

var headerCT = http.CanonicalHeaderKey("Content-Type")

// NewOpenAPI3Validator - Create a router for OPenAPI3 based specifications
// preferring yaml for the spec file
func NewOpenAPI3Validator(spectype spec.Type, version semver.Version) (Validator, error) {
	return buildValidator(spectype, version)
}

// NewRawOpenAPI3Validator -
func NewRawOpenAPI3Validator(spectype spec.Type, version semver.Version) (OpenAPI3Validator, error) {
	return buildValidator(spectype, version)
}

func buildValidator(spectype spec.Type, version semver.Version) (OpenAPI3Validator, error) {
	router, doc, err := getRouterForSpec(spectype, version)
	return OpenAPI3Validator{router: router, doc: doc}, err
}

// IsRequestProperty - Find param in schema and determines if it's part of request body
func (v OpenAPI3Validator) IsRequestProperty(checkmethod, checkpath, propertyPath string) (bool, string, error) {
	spec := v.doc
	for path, props := range spec.Paths {
		for method, op := range getOas3Operations(props) {
			if path == checkpath && method == checkmethod && op.RequestBody != nil {
				for _, param := range op.RequestBody.Value.Content {
					schema := param.Schema.Value
					found, objType := findPropertyInOas3Schema(schema, propertyPath, "")
					if found {
						return true, objType, nil
					}
				}
			}
		}
	}

	return false, "", nil
}

// GetRouterForSpec - to match schema path validation
func getRouterForSpec(spectype spec.Type, version semver.Version) (routers.Router, *openapi3.T, error) {

	specFileName, err := spec.GetSpecFilePathPattern(spectype, version)
	if err != nil {
		return nil, nil, errors.New("cannot get router for spec: " + spectype.String() + " " + version.String())
	}

	doc, err := loadSpecFromData(specFileName)

	if err != nil {
		return nil, nil, fmt.Errorf("cannot Load OpenApi Spec from file %s, %s", specFileName, err)
	}

	err = doc.Validate(context.Background())
	if err != nil {
		return nil, nil, fmt.Errorf("cannot Load OpenApi Spec from file %s, %s", specFileName, err)
	}

	router, err := legacyrouter.NewRouter(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot Load OpenApi Router for %s:%s file %s", spectype, version.String(), specFileName)
	}

	return router, doc, nil
}

func loadSpecFromData(filename string) (*openapi3.T, error) {
	loader := openapi3.NewLoader()

	bytes, err := resources.Specs.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return loader.LoadFromData(bytes)
}

// Validate - validates the response
func (v OpenAPI3Validator) Validate(r HTTPResponse) ([]Failure, error) {
	failures := []Failure{}

	u, err := url.Parse(r.Path)
	if err != nil {
		return nil, err
	}
	path := u.Path

	// serverPath := v.doc.Servers[0].URL
	// var path string
	// serverIndex := strings.Index(r.Path, serverPath)
	// if serverIndex != -1 {
	// 	path = r.Path[serverIndex:]
	// } else {
	// 	path = serverPath + r.Path
	// }

	httpReq, err := createHTTPReq(r.Method, path)
	if err != nil {
		return nil, err
	}

	route, pathParams, err := v.router.FindRoute(httpReq)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("OpenApi3Validator: error converting body %s", err)
	}

	// check body
	params := validateParams{
		httpReq:    httpReq,
		route:      route,
		pathParams: pathParams,
		statusCode: r.StatusCode,
		header:     r.Header,
		body:       body,
	}

	// accumulate failures
	err = v.validateResponse(params)
	if err != nil {
		return nil, fmt.Errorf("Validate error response:  %s", err.Error())
	}

	return failures, nil
}

func (v OpenAPI3Validator) validateResponse(params validateParams) error {
	requestValidationInput := &openapi3filter.RequestValidationInput{
		Request:    params.httpReq,
		PathParams: params.pathParams,
		Route:      params.route,
	}

	responseValidationInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: requestValidationInput,
		Status:                 params.statusCode,
		Header:                 params.header,
		Options: &openapi3filter.Options{
			ExcludeRequestBody:    true,
			IncludeResponseStatus: true,
			MultiError:            false,
		},
	}

	if len(params.body) > 0 {
		responseValidationInput.SetBodyBytes(params.body)
	}

	return openapi3filter.ValidateResponse(context.Background(), responseValidationInput)
}

// FindRoute --
func (v OpenAPI3Validator) FindRoute(req *http.Request) (*routers.Route, map[string]string, error) {
	route, pathParams, err := v.router.FindRoute(req)
	if err != nil {
		return nil, nil, fmt.Errorf("%s %s - findTestRoute:  %s", req.Method, req.URL, err)
	}
	return route, pathParams, err
}

func createHTTPReq(method, path string) (*http.Request, error) {
	req, err := http.NewRequest(method, path, strings.NewReader(""))
	req.Header = http.Header{"Content-type": []string{"application/json; charset=utf-8"}}
	return req, err
}

// getOperations returns a mapping of HTTP Verb name to "spec operation name"
func getOas3Operations(props *openapi3.PathItem) map[string]*openapi3.Operation {
	ops := map[string]*openapi3.Operation{
		"DELETE":  props.Delete,
		"GET":     props.Get,
		"HEAD":    props.Head,
		"OPTIONS": props.Options,
		"PATCH":   props.Patch,
		"POST":    props.Post,
		"PUT":     props.Put,
	}

	// Keep those != nil
	for key, op := range ops {
		if op == nil {
			delete(ops, key)
		}
	}
	return ops
}

// normalizePropertyType - Workaround to provide similar context to the one used in Swagger schema
func normalizePropertyType(propertyType string) string {
	return fmt.Sprintf("[%s]", propertyType)
}

func findPropertyInOas3Schema(sc *openapi3.Schema, propertyPath, previousPath string) (bool, string) {
	for k, j := range sc.Properties {
		var element string
		if len(previousPath) == 0 {
			element = k
		} else {
			element = previousPath + "." + k
		}

		if element == propertyPath {
			return true, fmt.Sprintf("%s", normalizePropertyType(j.Value.Type))
		}

		ret, propType := findPropertyInOas3Schema(j.Value, propertyPath, element)
		if ret {
			return true, propType
		}
	}

	return findItemInOas3Schema(sc, propertyPath, previousPath)
}

func findItemInOas3Schema(sc *openapi3.Schema, propertyPath, previousPath string) (bool, string) {
	if len(sc.Properties) == 0 {
		notFoundPath := strings.Replace(propertyPath, previousPath+".", "", 1)
		SplitedNotFoundPath := strings.Split(notFoundPath, ".")
		idx := SplitedNotFoundPath[0]
		if _, err := strconv.Atoi(idx); err == nil {
			if len(SplitedNotFoundPath) == 1 {
				return true, normalizePropertyType(sc.Items.Value.Type)
			}
			element := previousPath + "." + idx
			ret, propType := findPropertyInOas3Schema(sc.Items.Value, propertyPath, element)
			if ret {
				return true, propType
			}
		}
	}

	return false, ""
}
