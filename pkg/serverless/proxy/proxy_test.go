// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package proxy

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/pkg/serverless/invocationlifecycle"
)

type testProcessorResponseValid struct{}

func (tp *testProcessorResponseValid) GetExecutionInfo() *invocationlifecycle.ExecutionStartInfo {
	return nil
}

func (tp *testProcessorResponseValid) OnInvokeStart(startDetails *invocationlifecycle.InvocationStartDetails) {
	if startDetails.StartTime.IsZero() {
		panic("isZero")
	}
	if !bytes.HasSuffix(startDetails.InvokeEventRawPayload, []byte("ok")) {
		panic("payload")
	}
}

func (tp *testProcessorResponseValid) OnInvokeEnd(endDetails *invocationlifecycle.InvocationEndDetails) {
	if endDetails.IsError != false {
		panic("isError")
	}
	if endDetails.EndTime.IsZero() {
		panic("isZero")
	}
}

type testProcessorResponseError struct{}

func (tp *testProcessorResponseError) OnInvokeStart(startDetails *invocationlifecycle.InvocationStartDetails) {
	if startDetails.StartTime.IsZero() {
		panic("isZero")
	}
	if !bytes.HasSuffix(startDetails.InvokeEventRawPayload, []byte("ok")) {
		panic("payload")
	}
}

func (tp *testProcessorResponseError) OnInvokeEnd(endDetails *invocationlifecycle.InvocationEndDetails) {
	if endDetails.IsError != true {
		panic("isError")
	}
}

func (tp *testProcessorResponseError) GetExecutionInfo() *invocationlifecycle.ExecutionStartInfo {
	return nil
}

func TestProxyResponseValid(t *testing.T) {
	if os.Getenv("CI") == "true" && runtime.GOOS == "darwin" {
		t.Skip("TestProxyResponseValid is known to fail on the macOS Gitlab runners because of the already running Agent")
	}
	// fake the runtime API running on 5001
	l, err := net.Listen("tcp", "127.0.0.1:5001")
	assert.Nil(t, err)

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "ok")
	}))
	ts.Listener.Close()
	ts.Listener = l
	ts.Start()
	defer ts.Close()

	t.Setenv("DD_EXPERIMENTAL_ENABLE_PROXY", "true")

	defer startServer(t, "127.0.0.1:5000", "127.0.0.1:5001", &testProcessorResponseValid{})()
	time.Sleep(100 * time.Millisecond)
	resp, err := http.Get("http://127.0.0.1:5000/xxx/next")
	assert.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()
	resp, err = http.Post("http://127.0.0.1:5000/xxx/response", "text/plain", strings.NewReader("bla bla bla"))
	assert.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()
}

func TestProxyResponseError(t *testing.T) {
	// fake the runtime API running on 6001
	l, err := net.Listen("tcp", "127.0.0.1:6001")
	assert.Nil(t, err)

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "ok")
	}))
	ts.Listener.Close()
	ts.Listener = l
	ts.Start()
	defer ts.Close()

	t.Setenv("DD_EXPERIMENTAL_ENABLE_PROXY", "true")

	defer startServer(t, "127.0.0.1:6000", "127.0.0.1:6001", &testProcessorResponseError{})()
	time.Sleep(100 * time.Millisecond)
	resp, err := http.Get("http://127.0.0.1:6000/xxx/next")
	assert.Nil(t, err)
	resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
	resp, err = http.Post("http://127.0.0.1:6000/xxx/error", "text/plain", strings.NewReader("bla bla bla"))
	assert.Nil(t, err)
	assert.Equal(t, 200, resp.StatusCode)

	resp.Body.Close()
}

func startServer(t *testing.T, proxyHostPort, originalRuntimeHostPort string, processor invocationlifecycle.InvocationProcessor) func() {
	shutdownChan := make(chan func(context.Context) error, 1)
	go setup(proxyHostPort, originalRuntimeHostPort, processor, shutdownChan)
	shutdown := <-shutdownChan
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.NoError(t, shutdown(ctx))
	}
}
