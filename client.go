package aws_signing_client

import (
	"bytes"
	"context"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/aws/aws-sdk-go/private/protocol/rest"
)

type (
	// Signer implements the http.RoundTripper interface and houses an optional RoundTripper that will be called between
	// signing and response.
	Signer struct {
		transport http.RoundTripper
		v4        *v4.Signer
		service   string
		region    string
		logger    ContextLogger
	}

	// ContextLogger is used for context-enabled logging.
	ContextLogger interface {
		Printf(ctx context.Context, format string, v ...interface{})
	}

	// DefaultLogger implements ContextLogger interface using log.Logger. This effectively means the context
	// is ignored.
	DefaultLogger struct {
		logger *log.Logger
	}

	// MissingSignerError is an implementation of the error interface that indicates that no AWS v4.Signer was
	// provided in order to create a client.
	MissingSignerError struct{}

	// MissingServiceError is an implementation of the error interface that indicates that no AWS service was
	// provided in order to create a client.
	MissingServiceError struct{}

	// MissingRegionError is an implementation of the error interface that indicates that no AWS region was
	// provided in order to create a client.
	MissingRegionError struct{}
)

// DefaultLogger.Printf() ignores the specified context.
func (dl *DefaultLogger) Printf(ctx context.Context, format string, v ...interface{}) {
	dl.logger.Printf(format, v...)
}

// New obtains an HTTP client with a RoundTripper that signs AWS requests for the provided service. An
// existing client can be specified for the `client` value, or--if nil--a new HTTP client will be created.
func New(v4s *v4.Signer, client *http.Client, service string, region string, cl ContextLogger) (*http.Client, error) {
	c := client
	switch {
	case v4s == nil:
		return nil, MissingSignerError{}
	case service == "":
		return nil, MissingServiceError{}
	case region == "":
		return nil, MissingRegionError{}
	case c == nil:
		c = http.DefaultClient
	}

	if cl == nil {
		cl = &DefaultLogger{
			logger: log.New(ioutil.Discard, "", 0),
		}
	}

	s := &Signer{
		transport: c.Transport,
		v4:        v4s,
		service:   service,
		region:    region,
		logger:    cl,
	}
	if s.transport == nil {
		s.transport = http.DefaultTransport
	}
	c.Transport = s
	return c, nil
}

// RoundTrip implements the http.RoundTripper interface and is used to wrap HTTP requests in order to sign them for AWS
// API calls. The scheme for all requests will be changed to HTTPS.
func (s *Signer) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if h, ok := req.Header["Authorization"]; ok && len(h) > 0 && strings.HasPrefix(h[0], "AWS4") {
		s.logger.Printf(ctx, "Received request to sign that is already signed. Skipping.")
		return s.transport.RoundTrip(req)
	}

	req.URL.Scheme = "https"
	if strings.Contains(req.URL.RawPath, "%2C") {
		s.logger.Printf(ctx, "Escaping path for URL path '%s'", req.URL.RawPath)
		req.URL.RawPath = rest.EscapePath(req.URL.RawPath, false)
	}
	t := time.Now()
	req.Header.Set("Date", t.Format(time.RFC3339))
	s.logger.Printf(ctx, "Request to be signed: %+v", req)

	var latency int64
	var err error
	switch req.Body {
	case nil:
		s.logger.Printf(ctx, "Signing request with no body...")
		start := time.Now()
		_, err = s.v4.Sign(req, nil, s.service, s.region, t)
		latency = int64(time.Now().Sub(start)/time.Millisecond)
	default:
		d, err := ioutil.ReadAll(req.Body)
		if err != nil {
			s.logger.Printf(ctx, "Error while attempting to read request body: '%s'", err)
			return nil, err
		}
		req.Body = ioutil.NopCloser(bytes.NewReader(d))
		s.logger.Printf(ctx, "Signing request with body...")
		start := time.Now()
		_, err = s.v4.Sign(req, bytes.NewReader(d), s.service, s.region, t)
		latency = int64(time.Now().Sub(start)/time.Millisecond)
	}

	if err != nil {
		s.logger.Printf(ctx, "Error while attempting to sign request: '%s'", err)
		return nil, err
	}
	s.logger.Printf(ctx, "Signing succesful. Latency: %d ms", latency)

	start := time.Now()
	resp, err := s.transport.RoundTrip(req)
	latency = int64(time.Now().Sub(start)/time.Millisecond)

	if err != nil {
		s.logger.Printf(ctx, "Error from RoundTripper. Latency: %d ms, Error: %s", latency, err)
		return resp, err
	}

	s.logger.Printf(ctx, "Successful response from RoundTripper. Latency: %d ms", latency)
	return resp, nil
}

// Error implements the error interface.
func (err MissingSignerError) Error() string {
	return "No signer was provided. Cannot create client."
}

// Error implements the error interface.
func (err MissingServiceError) Error() string {
	return "No AWS service abbreviation was provided. Cannot create client."
}

// Error implements the error interface.
func (err MissingRegionError) Error() string {
	return "No AWS region was provided. Cannot create client."
}
