// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package connectivity contains logic for connectivity troubleshooting between the Agent
// and Datadog endpoints. It uses HTTP request to contact different endpoints and displays
// some results depending on endpoints responses, if any.
package connectivity

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"

	"github.com/DataDog/datadog-agent/comp/core/config"
	diagnose "github.com/DataDog/datadog-agent/comp/core/diagnose/def"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	forwarder "github.com/DataDog/datadog-agent/comp/forwarder/defaultforwarder"
	"github.com/DataDog/datadog-agent/comp/forwarder/defaultforwarder/resolver"
	logsConfig "github.com/DataDog/datadog-agent/comp/logs/agent/config"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/config/utils"
	logshttp "github.com/DataDog/datadog-agent/pkg/logs/client/http"
	logstcp "github.com/DataDog/datadog-agent/pkg/logs/client/tcp"
	"github.com/DataDog/datadog-agent/pkg/util/scrubber"
)

func getLogsEndpoints(useTCP bool) (*logsConfig.Endpoints, error) {
	datadogConfig := pkgconfigsetup.Datadog()
	logsConfigKey := logsConfig.NewLogsConfigKeys("logs_config.", datadogConfig)

	var endpoints *logsConfig.Endpoints
	var err error

	if useTCP {
		endpoints, err = logsConfig.BuildEndpointsWithConfig(
			datadogConfig,
			logsConfigKey,
			"agent-http-intake.logs.",
			false,
			"logs",
			logsConfig.AgentJSONIntakeProtocol,
			logsConfig.DefaultIntakeOrigin)
	} else {
		endpoints, err = logsConfig.BuildHTTPEndpointsWithConfig(
			datadogConfig,
			logsConfigKey,
			"agent-http-intake.logs.",
			"logs",
			logsConfig.AgentJSONIntakeProtocol,
			logsConfig.DefaultIntakeOrigin)
	}

	return endpoints, err
}

// getLogsUseTCP returns true if the agent should use TCP to transport logs
func getLogsUseTCP() bool {
	datadogConfig := pkgconfigsetup.Datadog()
	useTCP := datadogConfig.GetBool("logs_config.force_use_tcp") && !datadogConfig.GetBool("logs_config.force_use_http")

	return useTCP
}

// Diagnose performs connectivity diagnosis
func Diagnose(diagCfg diagnose.Config, log log.Component) []diagnose.Diagnosis {

	// Create domain resolvers
	keysPerDomain, err := utils.GetMultipleEndpoints(pkgconfigsetup.Datadog())
	if err != nil {
		return []diagnose.Diagnosis{
			{
				Status:      diagnose.DiagnosisSuccess,
				Name:        "Endpoints configuration",
				Diagnosis:   "Misconfiguration of agent endpoints",
				Remediation: "Please validate Agent configuration",
				RawError:    err.Error(),
			},
		}
	}

	var diagnoses []diagnose.Diagnosis
	domainResolvers, err := resolver.NewSingleDomainResolvers(keysPerDomain)
	if err != nil {
		return []diagnose.Diagnosis{
			{
				Status:      diagnose.DiagnosisSuccess,
				Name:        "Resolver error",
				Diagnosis:   "Unable to create domain resolver",
				Remediation: "This is likely due to a bug",
				RawError:    err.Error(),
			},
		}
	}
	numberOfWorkers := 1
	client := forwarder.NewHTTPClient(pkgconfigsetup.Datadog(), numberOfWorkers, log)

	// Create diagnosis for logs
	if pkgconfigsetup.Datadog().GetBool("logs_enabled") {
		useTCP := getLogsUseTCP()
		endpoints, err := getLogsEndpoints(useTCP)

		if err != nil {
			diagnoses = append(diagnoses, diagnose.Diagnosis{
				Status:      diagnose.DiagnosisFail,
				Name:        "Endpoints configuration",
				Diagnosis:   "Misconfiguration of agent endpoints",
				Remediation: "Please validate agent configuration",
				RawError:    err.Error(),
			})
		} else {
			var url string
			connType := "HTTPS"
			if useTCP {
				connType = "TCP"
				url, err = logstcp.CheckConnectivityDiagnose(endpoints.Main, 5)
			} else {
				url, err = logshttp.CheckConnectivityDiagnose(endpoints.Main, pkgconfigsetup.Datadog())
			}

			name := fmt.Sprintf("%s connectivity to %s", connType, url)
			diag := createDiagnosis(name, url, "", err)

			diagnoses = append(diagnoses, diag)
		}

	}

	endpointsInfo := getEndpointsInfo(pkgconfigsetup.Datadog())

	// Send requests to all endpoints for all domains
	for _, domainResolver := range domainResolvers {
		// Go through all API Keys of a domain and send an HTTP request on each endpoint
		for _, apiKey := range domainResolver.GetAPIKeys() {
			for _, endpointInfo := range endpointsInfo {
				// Initialize variables
				var logURL string
				var responseBody []byte
				var err error
				var statusCode int
				var httpTraces []string

				if endpointInfo.Method == "HEAD" {
					logURL = endpointInfo.Endpoint.Route
					statusCode, err = sendHTTPHEADRequestToEndpoint(logURL, clientWithOneRedirects(pkgconfigsetup.Datadog(), numberOfWorkers, log))
				} else {
					domain, _ := domainResolver.Resolve(endpointInfo.Endpoint)
					httpTraces = []string{}
					ctx := httptrace.WithClientTrace(context.Background(), createDiagnoseTraces(&httpTraces))

					statusCode, responseBody, logURL, err = sendHTTPRequestToEndpoint(ctx, client, domain, endpointInfo, apiKey)
				}

				// Check if there is a response and if it's valid
				report, reportErr := verifyEndpointResponse(diagCfg, statusCode, responseBody, err)

				diagnosisName := "Connectivity to " + logURL
				d := createDiagnosis(diagnosisName, logURL, report, reportErr)

				// Prepend http trace on error or if in verbose mode
				if len(httpTraces) > 0 && (diagCfg.Verbose || reportErr != nil) {
					d.Diagnosis = fmt.Sprintf("\n%s\n%s", strings.Join(httpTraces, "\n"), d.Diagnosis)
				}
				diagnoses = append(diagnoses, d)
			}
		}
	}
	return diagnoses
}

func createDiagnosis(name string, logURL string, report string, err error) diagnose.Diagnosis {
	d := diagnose.Diagnosis{
		Name: name,
	}

	if err == nil {
		d.Status = diagnose.DiagnosisSuccess
		diagnosisWithoutReport := fmt.Sprintf("Connectivity to `%s` is Ok", logURL)
		d.Diagnosis = createDiagnosisString(diagnosisWithoutReport, report)
	} else {
		d.Status = diagnose.DiagnosisFail
		diagnosisWithoutReport := fmt.Sprintf("Connection to `%s` failed", logURL)
		d.Diagnosis = createDiagnosisString(diagnosisWithoutReport, report)
		d.Remediation = "Please validate Agent configuration and firewall to access " + logURL
		d.RawError = err.Error()
	}

	return d
}

func createDiagnosisString(diagnosis string, report string) string {
	if len(report) == 0 {
		return diagnosis
	}

	return fmt.Sprintf("%v\n%v", diagnosis, report)
}

// sendHTTPRequestToEndpoint creates an URL based on the domain and the endpoint information
// then sends an HTTP Request with the method and payload inside the endpoint information
func sendHTTPRequestToEndpoint(ctx context.Context, client *http.Client, domain string, endpointInfo endpointInfo, apiKey string) (int, []byte, string, error) {
	url := createEndpointURL(domain, endpointInfo)
	logURL := scrubber.ScrubLine(url)

	// Create a request for the backend
	reader := bytes.NewReader(endpointInfo.Payload)
	req, err := http.NewRequest(endpointInfo.Method, url, reader)

	if err != nil {
		return 0, nil, logURL, fmt.Errorf("cannot create request for transaction to invalid URL '%v' : %v", logURL, scrubber.ScrubLine(err.Error()))
	}

	// Add tracing and send the request
	req = req.WithContext(ctx)
	contentType := endpointInfo.ContentType
	if contentType == "" {
		contentType = "application/json"
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("DD-API-KEY", apiKey)

	resp, err := client.Do(req)

	if err != nil {
		return 0, nil, logURL, fmt.Errorf("cannot send the HTTP request to '%v' : %v", logURL, scrubber.ScrubLine(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()

	// Get the endpoint response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, logURL, fmt.Errorf("fail to read the response Body: %s", scrubber.ScrubLine(err.Error()))
	}

	return resp.StatusCode, body, logURL, nil
}

// createEndpointUrl joins a domain with an endpoint
func createEndpointURL(domain string, endpointInfo endpointInfo) string {
	return domain + endpointInfo.Endpoint.Route
}

// vertifyEndpointResponse interprets the endpoint response and displays information on if the connectivity
// check was successful or not
func verifyEndpointResponse(diagCfg diagnose.Config, statusCode int, responseBody []byte, err error) (string, error) {

	if err != nil {
		return fmt.Sprintf("Could not get a response from the endpoint : %v\n%s\n",
			scrubber.ScrubLine(err.Error()), noResponseHints(err)), err
	}

	var verifyReport string
	var newErr error

	limitSize := 500

	scrubbedResponseBody := scrubber.ScrubLine(string(responseBody))
	if !diagCfg.Verbose && len(scrubbedResponseBody) > limitSize {
		scrubbedResponseBody = scrubbedResponseBody[:limitSize] + "...\n"
		scrubbedResponseBody += fmt.Sprintf("Response body is %v bytes long, truncated at %v\n", len(responseBody), limitSize)
		scrubbedResponseBody += "To display the whole body use the \"--verbose\" flag."
	}

	if statusCode >= 400 {
		newErr = fmt.Errorf("bad request")
		verifyReport = fmt.Sprintf("Received response : '%v'\n", scrubbedResponseBody)
	}

	verifyReport += fmt.Sprintf("Received status code %v from the endpoint", statusCode)
	return verifyReport, newErr
}

// noResponseHints aims to give hints when the endpoint did not respond.
// For instance, when sending an HTTP request to a HAProxy endpoint configured for HTTPS
// the endpoint send an empty response. As the error 'EOF' is not very informative, it can
// be interesting to 'wrap' this error to display more context.
func noResponseHints(err error) string {
	endpoint := utils.GetInfraEndpoint(pkgconfigsetup.Datadog())
	parsedURL, parseErr := url.Parse(endpoint)
	if parseErr != nil {
		return fmt.Sprintf("Could not parse url '%v' : %v", scrubber.ScrubLine(endpoint), scrubber.ScrubLine(parseErr.Error()))
	}

	if parsedURL.Scheme == "http" {
		if strings.Contains(err.Error(), "EOF") {
			return fmt.Sprintf("Hint: received an empty reply from the server. You are maybe trying to contact an HTTPS endpoint using an HTTP url: '%v'\n",
				scrubber.ScrubLine(endpoint))
		}
	}

	return ""
}

func clientWithOneRedirects(config config.Component, numberOfWorkers int, log log.Component) *http.Client {
	return &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: forwarder.NewHTTPTransport(
			config,
			numberOfWorkers,
			log),
	}
}

// See if the URL is redirected to another URL, and return the status code of the redirection
func sendHTTPHEADRequestToEndpoint(url string, client *http.Client) (int, error) {
	res, err := client.Head(url)
	if err != nil {
		return -1, err
	}
	defer res.Body.Close()
	// Expected status codes are OK or a redirection
	if res.StatusCode == http.StatusTemporaryRedirect || res.StatusCode == http.StatusPermanentRedirect || res.StatusCode == http.StatusOK {
		return res.StatusCode, nil
	}
	return res.StatusCode, fmt.Errorf("The request wasn't redirected nor achieving his goal: %v", res.Status)
}
