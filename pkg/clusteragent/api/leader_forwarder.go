// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package api contains the telemetry of the Cluster Agent API and implements
// the forwarding of queries from Cluster Agent followers to the leader.
package api

import (
	"crypto/tls"
	"fmt"
	stdLog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/log"
	pkglogsetup "github.com/DataDog/datadog-agent/pkg/util/log/setup"
)

const (
	forwardHeader = "X-DCA-Follower-Forwarded"
	respForwarded = "X-DCA-Forwarded"
)

// globalLeaderForwarder is the global LeaderForwarder instance
var globalLeaderForwarder *LeaderForwarder

// LeaderForwarder allows to forward queries from follower to leader
type LeaderForwarder struct {
	transport http.RoundTripper
	logger    *stdLog.Logger
	proxy     *httputil.ReverseProxy
	proxyLock sync.RWMutex
	apiPort   string
	leaderIP  string
}

// NewLeaderForwarder initializes a new LeaderForwarder instance and is used for test purposes
func NewLeaderForwarder(apiPort, maxConnections int) *LeaderForwarder {
	// Use a stack depth of 4 on top of the default one to get a relevant filename in the stdlib
	logWriter, _ := pkglogsetup.NewLogWriter(4, log.DebugLvl)
	return &LeaderForwarder{
		apiPort:  strconv.Itoa(apiPort),
		leaderIP: "",
		transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   1 * time.Second,
				KeepAlive: 20 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     false,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout:   5 * time.Second,
			MaxConnsPerHost:       maxConnections,
			MaxIdleConnsPerHost:   maxConnections,
			MaxIdleConns:          0,
			IdleConnTimeout:       120 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		logger: stdLog.New(logWriter, "Error while forwarding to leader DCA: ", 0), // log errors to seelog,
	}
}

// NewGlobalLeaderForwarder initializes the global LeaderForwarder instance
func NewGlobalLeaderForwarder(apiPort, maxConnections int) {
	if globalLeaderForwarder != nil {
		return
	}

	globalLeaderForwarder = NewLeaderForwarder(apiPort, maxConnections)
}

// GetGlobalLeaderForwarder returns the global LeaderForwarder instance
func GetGlobalLeaderForwarder() *LeaderForwarder {
	return globalLeaderForwarder
}

// Forward forwards a query to leader if available
func (lf *LeaderForwarder) Forward(rw http.ResponseWriter, req *http.Request) {
	// Always set Forwarded header in reply
	rw.Header().Set(respForwarded, "true")

	if req.Header.Get(forwardHeader) != "" {
		http.Error(rw, fmt.Sprintf("Query was already forwarded from: %s", req.RemoteAddr), http.StatusLoopDetected)
	}

	var currentProxy *httputil.ReverseProxy
	lf.proxyLock.RLock()
	currentProxy = lf.proxy
	lf.proxyLock.RUnlock()

	if currentProxy == nil {
		http.Error(rw, "", http.StatusServiceUnavailable)
		return
	}

	currentProxy.ServeHTTP(rw, req)
}

// SetLeaderIP allows to change the target leader IP
func (lf *LeaderForwarder) SetLeaderIP(leaderIP string) {
	lf.proxyLock.Lock()
	defer lf.proxyLock.Unlock()

	if leaderIP == "" {
		lf.proxy = nil
		return
	}
	lf.leaderIP = leaderIP
	lf.proxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "https"
			req.URL.Host = leaderIP + ":" + lf.apiPort
			req.Header.Add(forwardHeader, "true")
		},
		Transport: lf.transport,
		ErrorLog:  lf.logger,
	}
}

// GetLeaderIP allows to GET current leader IP
func (lf *LeaderForwarder) GetLeaderIP() string {
	lf.proxyLock.RLock()
	defer lf.proxyLock.RUnlock()
	return lf.leaderIP
}
