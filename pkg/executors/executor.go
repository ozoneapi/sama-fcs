package executors

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"

	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/auth"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/auth/certificates"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/executors/results"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/httpclient"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/model"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/tracer"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/go-resty/resty/v2"
)

// TestCaseExecutor defines an interface capable of executing a testcase
type TestCaseExecutor interface {
	ExecuteTestCase(r *resty.Request, t *model.TestCase, ctx *model.Context) (*resty.Response, results.Metrics, error)
	SetCertificates(certificateSigning, certificationTransport auth.Certificate) error
	HTTPClient() *resty.Client
}

// NewExecutor creates an executor
func NewExecutor() TestCaseExecutor {
	client := httpclient.NewClient()
	return &Executor{RestyClient: client}
}

// Executor - passes request to system under test across an matls connection
type Executor struct {
	SigningCert   auth.Certificate
	TransportCert auth.Certificate
	RestyClient   *resty.Client
}

// HTTPClient - access to underlying resty httpClient
func (e *Executor) HTTPClient() *resty.Client {
	return e.RestyClient
}

// SetCertificates receives transport and signing certificates
func (e *Executor) SetCertificates(certificateSigning, certificationTransport auth.Certificate) error {
	e.SigningCert = certificateSigning
	e.TransportCert = certificationTransport
	return e.setupTLSCertificate(e.TransportCert.TLSCert())
}

// ExecuteTestCase - makes this a generic executor
func (e *Executor) ExecuteTestCase(r *resty.Request, t *model.TestCase, ctx *model.Context) (*resty.Response, results.Metrics, error) {
	if t.DoNotCallEndpoint {
		e.appMsg(fmt.Sprintf("Not executing Testcase: %s: %s", t.ID, t.Name))
		return emptyResponse(), results.NoMetrics(), nil
	}

	e.appMsg(fmt.Sprintf("Execute Testcase: %s: %s", t.ID, t.Name))
	e.appMsg(fmt.Sprintf("attempting %s %s", r.Method, r.URL))
	resp, err := r.Execute(r.Method, r.URL)
	if err != nil {
		if resp.StatusCode() == http.StatusFound { // catch status code 302 redirects and pass back as good response
			header := resp.Header()
			t.StatusCode = resp.Status()
			logrus.StandardLogger().Printf("redirection headers: %#v\n", header)
			e.appMsg(fmt.Sprintf("Response: (%.250s)", resp.String()))
			return resp, metrics(t, resp), nil
		}
	}
	t.StatusCode = resp.Status()
	var elipsis string
	if len(resp.String()) > 450 {
		elipsis = " ..."
	}
	e.appMsg(fmt.Sprintf("Response: (%.450s)%s", resp.String(), elipsis))
	return resp, metrics(t, resp), err
}

func metrics(testCase *model.TestCase, response *resty.Response) results.Metrics {
	return results.NewMetricsFromRestyResponse(testCase, response)
}

func (e *Executor) setupTLSCertificate(tlsCert tls.Certificate) error {
	mycert = tlsCert // hack
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		return errors.New("setupTLSCertificate SystemCertPool:" + err.Error())
	}
	if ok := caCertPool.AppendCertsFromPEM(certificates.OpenBankingSandBoxIssuingCA()); !ok {
		return errors.New("setupTLSCertificate failed to append OpenBankingSandBoxIssuingCA")
	}
	if ok := caCertPool.AppendCertsFromPEM(certificates.OpenBankingSandBoxRootCA()); !ok {
		return errors.New("setupTLSCertificate failed to append OpenBankingSandBoxRootCA")
	}
	if ok := caCertPool.AppendCertsFromPEM(certificates.OpenBankingIssuingCA()); !ok {
		return errors.New("setupTLSCertificate failed to append OpenBankingIssuingCA")
	}
	if ok := caCertPool.AppendCertsFromPEM(certificates.OpenBankingRootCA()); !ok {
		return errors.New("setupTLSCertificate failed to append OpenBankingRootCA")
	}

	tlsConfig := &tls.Config{
		Certificates:         []tls.Certificate{tlsCert},
		RootCAs:              caCertPool,
		InsecureSkipVerify:   true,
		MinVersion:           tls.VersionTLS12,
		Renegotiation:        tls.RenegotiateFreelyAsClient,
		GetClientCertificate: GetCertificate,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
	tlsConfig.BuildNameToCertificate()
	client := httpclient.NewClient()
	client.SetTLSClientConfig(tlsConfig)
	return nil
}

func (e *Executor) appMsg(msg string) {
	tracer.AppMsg("Executor", msg, "")
}

func emptyResponse() *resty.Response {
	return &resty.Response{
		Request: &resty.Request{},
		RawResponse: &http.Response{
			Body:       ioutil.NopCloser(bytes.NewReader([]byte(`{}`))),
			Status:     "-1 Ignore",
			StatusCode: -1,
		},
	}
}

var mycert tls.Certificate

// GetCertificate - select certificate to send as part of matls handshake
func GetCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return &mycert, nil
}
