// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//nolint:revive // TODO(ASM) Fix revive linter
//nolint:deadcode,unused
package httpsec

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/DataDog/appsec-internal-go/httpsec"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/go-libddwaf/v4"
	json "github.com/json-iterator/go"
)

// envClientIPHeader is the name of the env var used to specify the IP header to be used for client IP collection.
const envClientIPHeader = "DD_TRACE_CLIENT_IP_HEADER"

var (
	defaultIPHeaders = []string{
		"x-forwarded-for",
		"x-real-ip",
		"x-client-ip",
		"x-forwarded",
		"x-cluster-client-ip",
		"forwarded-for",
		"forwarded",
		"via",
		"true-client-ip",
	}

	// Configured list of IP-related headers leveraged to retrieve the public
	// client IP address. Defined at init-time in the init() function below.
	monitoredClientIPHeadersCfg []string

	// List of HTTP headers we collect and send.
	collectedHTTPHeaders = append(defaultIPHeaders,
		"host",
		"content-length",
		"content-type",
		"content-encoding",
		"content-language",
		"forwarded",
		"user-agent",
		"accept",
		"accept-encoding",
		"accept-language")
)

func init() {
	if cfg := os.Getenv(envClientIPHeader); cfg != "" {
		// Collect this header value too
		collectedHTTPHeaders = append(collectedHTTPHeaders, cfg)
		// Set this IP header as the only one to consider for ClientIP()
		monitoredClientIPHeadersCfg = []string{cfg}
	} else {
		monitoredClientIPHeadersCfg = defaultIPHeaders
	}

	// Ensure the list of headers are sorted for sort.SearchStrings()
	sort.Strings(collectedHTTPHeaders[:])
}

// span interface expected by this package to set span tags.
type span interface {
	SetMetaTag(tag string, value string)
	SetMetricsTag(tag string, value float64)
	GetMetaTag(tag string) (value string, exists bool)
}

// setAppSecEnabledTags sets the AppSec-specific span tags that are expected to
// be in service entry span when AppSec is enabled.
func setAppSecEnabledTags(span span) {
	span.SetMetricsTag("_dd.appsec.enabled", 1)
}

// setEventSpanTags sets the security event span tags into the service entry span.
func setEventSpanTags(span span, events []any) error {
	// Set the appsec event span tag
	val, err := makeEventsTagValue(events)
	if err != nil {
		return err
	}
	span.SetMetaTag("_dd.appsec.json", string(val))

	// Set the appsec.event tag needed by the appsec backend
	span.SetMetaTag("_dd.origin", "appsec")
	span.SetMetaTag("appsec.event", "true")
	return nil
}

// Create the value of the security events tag.
func makeEventsTagValue(events []any) (json.RawMessage, error) {
	// Create the structure to use in the `_dd.appsec.json` span tag.
	tag, err := json.Marshal(struct {
		Triggers []any `json:"triggers"`
	}{Triggers: events})
	if err != nil {
		return nil, fmt.Errorf("unexpected error while serializing the appsec event span tag: %v", err)
	}
	return tag, nil
}

// setSecurityEventsTags sets the AppSec-specific span tags when security events were found.
func setSecurityEventsTags(span span, events []any, headers, respHeaders map[string][]string) {
	if err := setEventSpanTags(span, events); err != nil {
		log.Errorf("appsec: unexpected error while creating the appsec event tags: %v", err)
		return
	}
	for h, v := range normalizeHTTPHeaders(headers) {
		span.SetMetaTag("http.request.headers."+h, v)
	}
	for h, v := range normalizeHTTPHeaders(respHeaders) {
		span.SetMetaTag("http.response.headers."+h, v)
	}
}

// setAPISecurityEventsTags sets the AppSec-specific span tags related to API security schemas
func setAPISecurityTags(span span, derivatives map[string]any) {
	for key, val := range derivatives {
		if rawVal, err := json.Marshal(val); err != nil {
			log.Errorf("appsec: unexpected error while creating the API security tags: %v", err)
		} else {
			span.SetMetaTag(key, string(rawVal))
		}
	}
}

// normalizeHTTPHeaders returns the HTTP headers following Datadog's
// normalization format.
func normalizeHTTPHeaders(headers map[string][]string) (normalized map[string]string) {
	if len(headers) == 0 {
		return nil
	}
	normalized = make(map[string]string)
	for k, v := range headers {
		k = strings.ToLower(k)
		if i := sort.SearchStrings(collectedHTTPHeaders[:], k); i < len(collectedHTTPHeaders) && collectedHTTPHeaders[i] == k {
			normalized[k] = strings.Join(v, ",")
		}
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

// setClientIPTags sets the http.client_ip, http.request.headers.*, and
// network.client.ip span tags according to the request headers and remote
// connection address. Note that the given request headers reqHeaders must be
// normalized with lower-cased keys for this function to work.
func setClientIPTags(span span, remoteAddr string, reqHeaders map[string][]string) {
	remoteIP, clientIP := httpsec.ClientIP(reqHeaders, false, remoteAddr, monitoredClientIPHeadersCfg)
	tags := httpsec.ClientIPTags(remoteIP, clientIP)

	for k, v := range tags {
		span.SetMetaTag(k, v)
	}
}

// setRulesMonitoringTags adds the tags related to security rules monitoring
// It's only needed once per handle initialization as the ruleset data does not
// change over time.
func setRulesMonitoringTags(span span, wafDiags libddwaf.Diagnostics) {
	rInfo := wafDiags.Rules
	if rInfo == nil {
		return
	}

	var rulesetErrors []byte
	var err error
	rulesetErrors, err = json.Marshal(wafDiags.Rules.Errors)
	if err != nil {
		log.Error("appsec: could not marshal the waf ruleset info errors to json")
	}
	span.SetMetaTag("_dd.appsec.event_rules.errors", string(rulesetErrors))
	span.SetMetaTag("_dd.appsec.event_rules.loaded", strconv.Itoa(len(rInfo.Loaded)))
	span.SetMetaTag("_dd.appsec.event_rules.error_count", strconv.Itoa(len(rInfo.Failed)))
	span.SetMetaTag("_dd.appsec.waf.version", libddwaf.Version())
}

// setWAFMonitoringTags adds the tags related to the monitoring of the WAF performances
func setWAFMonitoringTags(span span, mRes *MonitorResult) {
	// Rules version is set for every request to help the backend associate Feature duration metrics with rule version
	span.SetMetaTag("_dd.appsec.event_rules.version", mRes.Diagnostics.Version)

	// Report the stats sent by the Feature
	for k, v := range mRes.Timings {
		span.SetMetaTag("_dd.appsec."+string(k), fmt.Sprintf("%v", v))
	}
}
