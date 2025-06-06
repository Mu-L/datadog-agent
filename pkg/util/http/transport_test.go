// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package http

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	configmock "github.com/DataDog/datadog-agent/pkg/config/mock"
	pkgconfigmodel "github.com/DataDog/datadog-agent/pkg/config/model"
)

func TestEmptyProxy(t *testing.T) {
	setupTest(t)

	r, err := http.NewRequest("GET", "https://test.com", nil)
	require.NoError(t, err)

	proxies := &pkgconfigmodel.Proxy{}
	c := configmock.New(t)
	proxyFunc := GetProxyTransportFunc(proxies, c)

	proxyURL, err := proxyFunc(r)
	assert.NoError(t, err)
	assert.Nil(t, proxyURL)
}

func TestHTTPProxy(t *testing.T) {
	setupTest(t)

	rHTTP, _ := http.NewRequest("GET", "http://test.com/api/v1?arg=21", nil)
	rHTTPS, _ := http.NewRequest("GET", "https://test.com/api/v1?arg=21", nil)

	proxies := &pkgconfigmodel.Proxy{
		HTTP: "https://user:pass@proxy.com:3128",
	}
	c := configmock.New(t)
	proxyFunc := GetProxyTransportFunc(proxies, c)

	proxyURL, err := proxyFunc(rHTTP)
	assert.NoError(t, err)
	assert.Equal(t, "https://user:pass@proxy.com:3128", proxyURL.String())

	proxyURL, err = proxyFunc(rHTTPS)
	assert.NoError(t, err)
	assert.Nil(t, proxyURL)
}

func TestNoProxy(t *testing.T) {
	setupTest(t)

	r1, _ := http.NewRequest("GET", "http://test_no_proxy.com/api/v1?arg=21", nil)
	r2, _ := http.NewRequest("GET", "http://test_http.com/api/v1?arg=21", nil)
	r3, _ := http.NewRequest("GET", "https://test_https.com/api/v1?arg=21", nil)
	r4, _ := http.NewRequest("GET", "http://sub.test_no_proxy.com/api/v1?arg=21", nil)

	proxies := &pkgconfigmodel.Proxy{
		HTTP:    "https://user:pass@proxy.com:3128",
		HTTPS:   "https://user:pass@proxy_https.com:3128",
		NoProxy: []string{"test_no_proxy.com", "test.org"},
	}
	c := configmock.New(t)

	proxyFunc := GetProxyTransportFunc(proxies, c)

	proxyURL, err := proxyFunc(r1)
	assert.NoError(t, err)
	assert.Nil(t, proxyURL)

	proxyURL, err = proxyFunc(r2)
	assert.NoError(t, err)
	assert.Equal(t, "https://user:pass@proxy.com:3128", proxyURL.String())

	proxyURL, err = proxyFunc(r3)
	assert.NoError(t, err)
	assert.Equal(t, "https://user:pass@proxy_https.com:3128", proxyURL.String())

	// Validate the old behavior (when no_proxy_nonexact_match is false)
	proxyURL, err = proxyFunc(r4)
	assert.NoError(t, err)
	assert.Equal(t, "https://user:pass@proxy.com:3128", proxyURL.String())
}

func TestNoProxyNonexactMatch(t *testing.T) {
	setupTest(t)

	r1, _ := http.NewRequest("GET", "http://test_no_proxy.com/api/v1?arg=21", nil)
	r2, _ := http.NewRequest("GET", "http://test_http.com/api/v1?arg=21", nil)
	r3, _ := http.NewRequest("GET", "https://test_https.com/api/v1?arg=21", nil)
	r4, _ := http.NewRequest("GET", "http://sub.test_no_proxy.com/api/v1?arg=21", nil)
	r5, _ := http.NewRequest("GET", "http://no_proxy2.com/api/v1?arg=21", nil)
	r6, _ := http.NewRequest("GET", "http://sub.no_proxy2.com/api/v1?arg=21", nil)

	c := configmock.New(t)
	c.SetWithoutSource("no_proxy_nonexact_match", true)

	// Testing some nonexact matching cases as documented here: https://github.com/golang/net/blob/master/http/httpproxy/proxy.go#L38
	proxies := &pkgconfigmodel.Proxy{
		HTTP:    "https://user:pass@proxy.com:3128",
		HTTPS:   "https://user:pass@proxy_https.com:3128",
		NoProxy: []string{"test_no_proxy.com", "test.org", ".no_proxy2.com"},
	}
	proxyFunc := GetProxyTransportFunc(proxies, c)

	proxyURL, err := proxyFunc(r1)
	assert.NoError(t, err)
	assert.Nil(t, proxyURL)

	proxyURL, err = proxyFunc(r2)
	assert.NoError(t, err)
	assert.Equal(t, "https://user:pass@proxy.com:3128", proxyURL.String())

	proxyURL, err = proxyFunc(r3)
	assert.NoError(t, err)
	assert.Equal(t, "https://user:pass@proxy_https.com:3128", proxyURL.String())

	proxyURL, err = proxyFunc(r4)
	assert.NoError(t, err)
	assert.Nil(t, proxyURL)

	proxyURL, err = proxyFunc(r5)
	assert.NoError(t, err)
	assert.Equal(t, "https://user:pass@proxy.com:3128", proxyURL.String())

	proxyURL, err = proxyFunc(r6)
	assert.NoError(t, err)
	assert.Nil(t, proxyURL)
}

func TestErrorParse(t *testing.T) {
	setupTest(t)

	r1, _ := http.NewRequest("GET", "http://test_no_proxy.com/api/v1?arg=21", nil)

	proxies := &pkgconfigmodel.Proxy{
		HTTP: "21://test.com",
	}
	c := configmock.New(t)
	proxyFunc := GetProxyTransportFunc(proxies, c)

	proxyURL, err := proxyFunc(r1)
	assert.NotNil(t, err)
	assert.Nil(t, proxyURL)
}

func TestBadScheme(t *testing.T) {
	setupTest(t)

	r1, _ := http.NewRequest("GET", "ftp://test.com", nil)

	proxies := &pkgconfigmodel.Proxy{
		HTTP: "http://test.com",
	}
	c := configmock.New(t)
	proxyFunc := GetProxyTransportFunc(proxies, c)

	proxyURL, err := proxyFunc(r1)
	assert.NoError(t, err)
	assert.Nil(t, proxyURL)
}

func TestCreateHTTPTransport(t *testing.T) {
	c := configmock.New(t)

	c.SetWithoutSource("skip_ssl_validation", false)
	transport := CreateHTTPTransport(c)
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
	assert.Equal(t, transport.TLSClientConfig.MinVersion, uint16(tls.VersionTLS12))

	c.SetWithoutSource("skip_ssl_validation", true)
	transport = CreateHTTPTransport(c)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
	assert.Equal(t, transport.TLSClientConfig.MinVersion, uint16(tls.VersionTLS12))

	transport = CreateHTTPTransport(c)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
	assert.Equal(t, transport.TLSClientConfig.MinVersion, uint16(tls.VersionTLS12))

	transport = CreateHTTPTransport(c)
	assert.NotZero(t, transport.TLSHandshakeTimeout)

	c.SetWithoutSource("tls_handshake_timeout", time.Second)
	transport = CreateHTTPTransport(c)
	assert.Equal(t, transport.TLSHandshakeTimeout, time.Second)
}

func TestCreateHTTP1Transport(t *testing.T) {
	c := configmock.New(t)

	transport := CreateHTTPTransport(c)
	require.NotNil(t, transport)

	assert.Nil(t, transport.TLSNextProto)
}

func TestCreateHTTP2Transport(t *testing.T) {
	c := configmock.New(t)

	transport := CreateHTTPTransport(c, WithHTTP2())
	require.NotNil(t, transport)

	assert.NotNil(t, transport.TLSNextProto)
	assert.Contains(t, transport.TLSNextProto, "h2", "TLSNextProto should indicate HTTP/2 support")

	assert.Contains(t, transport.TLSClientConfig.NextProtos, "h2", "NextProtos should prefer HTTP/2")
	assert.Contains(t, transport.TLSClientConfig.NextProtos, "http/1.1", "NextProtos should allow fallback to HTTP/1.1")
}

func TestNoProxyWarningMap(t *testing.T) {
	setupTest(t)

	r1, _ := http.NewRequest("GET", "http://api.test_http.com/api/v1?arg=21", nil)

	proxies := &pkgconfigmodel.Proxy{
		HTTP:    "https://user:pass@proxy.com:3128",
		HTTPS:   "https://user:pass@proxy_https.com:3128",
		NoProxy: []string{"test_http.com"},
	}
	c := configmock.New(t)
	proxyFunc := GetProxyTransportFunc(proxies, c)

	proxyURL, err := proxyFunc(r1)
	assert.NoError(t, err)
	assert.Equal(t, "https://user:pass@proxy.com:3128", proxyURL.String())

	assert.True(t, noProxyIgnoredWarningMap["http://api.test_http.com"])
}

func TestMinTLSVersionFromConfig(t *testing.T) {
	setupTest(t)

	tests := []struct {
		minTLSVersion string
		expect        uint16
	}{
		{"tlsv1.0", tls.VersionTLS10},
		{"tlsv1.1", tls.VersionTLS11},
		{"tlsv1.2", tls.VersionTLS12},
		{"tlsv1.3", tls.VersionTLS13},
		// case-insensitive
		{"TlSv1.0", tls.VersionTLS10},
		{"TlSv1.3", tls.VersionTLS13},
		// defaults
		{"", tls.VersionTLS12},
		{"", tls.VersionTLS12},
		// invalid values
		{"tlsv1.9", tls.VersionTLS12},
		{"tlsv1.9", tls.VersionTLS12},
		{"blergh", tls.VersionTLS12},
		{"blergh", tls.VersionTLS12},
	}

	for _, test := range tests {
		t.Run(
			fmt.Sprintf("min_tls_version=%s", test.minTLSVersion),
			func(t *testing.T) {
				cfg := configmock.New(t)
				if test.minTLSVersion != "" {
					cfg.SetWithoutSource("min_tls_version", test.minTLSVersion)
				}
				got := minTLSVersionFromConfig(cfg)
				require.Equal(t, test.expect, got)
			})
	}
}
