package httpclient

import (
	"bufio"
	"fmt"
	"os"

	"github.com/go-resty/resty/v2"
)

var (
	httpLogFile *os.File
	httpDebug   bool
	client      *resty.Client
	logWriter   *bufio.Writer
	httplogger  *HTTPlogger
	debugOuput  bool
)

// HTTPlogger -
type HTTPlogger struct {
}

// NewHTTPlogger  -
func NewHTTPlogger() *HTTPlogger {
	var err error
	httpLogFile, err = os.OpenFile("http-trace.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		httpLogFile = os.Stderr
	}
	logWriter = bufio.NewWriter(httpLogFile)

	return &HTTPlogger{}
}

// Errorf -
func (m *HTTPlogger) Errorf(format string, v ...interface{}) {
	fmt.Fprintln(logWriter, "RESTY ERROR")
	fmt.Fprintf(logWriter, format, v...)
}

// Warnf  -
func (m *HTTPlogger) Warnf(format string, v ...interface{}) {
	fmt.Fprintln(logWriter, "RESTY WARN")
	fmt.Fprintf(logWriter, format, v...)
}

// Debugf  -
func (m *HTTPlogger) Debugf(format string, v ...interface{}) {
	fmt.Fprintf(logWriter, format, v...)
	logWriter.Flush()
}

// NewClient -
func NewClient() *resty.Client {
	if httplogger == nil {
		httplogger = NewHTTPlogger()
	}
	if client == nil {
		client = resty.New()
		client.SetDebug(debugOuput)
		client.SetLogger(httplogger)
		client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(15))
		client.SetHeader("User-Agent", "OzoneFCS/1.0")
	}
	return client
}

// SetDebug output flag for httpclient
func SetDebug(flag bool) {
	debugOuput = flag
}
