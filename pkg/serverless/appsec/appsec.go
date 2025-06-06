// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package appsec provides a simple Application Security Monitoring API for
// serverless.
package appsec

import (
	"context"
	"errors"
	"math/rand"
	"os"

	appsecLog "github.com/DataDog/appsec-internal-go/log"
	waf "github.com/DataDog/go-libddwaf/v3"
	wafErrors "github.com/DataDog/go-libddwaf/v3/errors"
	json "github.com/json-iterator/go"

	"github.com/DataDog/appsec-internal-go/limiter"

	"github.com/DataDog/datadog-agent/pkg/aggregator"
	"github.com/DataDog/datadog-agent/pkg/serverless/appsec/config"
	"github.com/DataDog/datadog-agent/pkg/serverless/appsec/httpsec"
	"github.com/DataDog/datadog-agent/pkg/serverless/proxy"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

//nolint:revive // TODO(ASM) Fix revive linter
func New(demux aggregator.Demultiplexer) (lp *httpsec.ProxyLifecycleProcessor, err error) {
	lp, _, err = NewWithShutdown(demux)
	return
}

// NewWithShutdown returns a new httpsec.ProxyLifecycleProcessor and a shutdown function that can be
// called to terminate the started proxy (releasing the bound port and closing the AppSec instance).
// This is mainly intended to be called in test code so that goroutines and ports are not leaked,
// but can be used in other code paths when it is useful to be able to perform a clean shut down.
func NewWithShutdown(demux aggregator.Demultiplexer) (lp *httpsec.ProxyLifecycleProcessor, shutdown func(context.Context) error, err error) {
	appsecInstance, err := newAppSec() // note that the assigned variable is in the parent scope
	if err != nil {
		log.Warnf("appsec: failed to start appsec: %v -- appsec features are not available!", err)
		// Nil-out the error so we don't incorrectly report it later on...
		err = nil
	} else if appsecInstance == nil {
		return nil, nil, nil // appsec disabled
	}

	lambdaRuntimeAPI := os.Getenv("AWS_LAMBDA_RUNTIME_API")
	if lambdaRuntimeAPI == "" {
		lambdaRuntimeAPI = "127.0.0.1:9001"
	}

	// AppSec monitors the invocations by acting as a proxy of the AWS Lambda Runtime API.
	lp = httpsec.NewProxyLifecycleProcessor(appsecInstance, demux)
	shutdownProxy := proxy.Start(
		"127.0.0.1:9000",
		lambdaRuntimeAPI,
		lp,
	)
	log.Debug("appsec: started successfully using the runtime api proxy monitoring mode")

	shutdown = func(ctx context.Context) error {
		err := shutdownProxy(ctx)
		if appsecInstance != nil {
			// Note: `errors.Join` discards any `nil` error it receives.
			err = errors.Join(err, appsecInstance.Close())
		}
		return err
	}

	return
}

//nolint:revive // TODO(ASM) Fix revive linter
type AppSec struct {
	cfg *config.Config
	// WAF handle instance of the appsec event rules.
	handle *waf.Handle
	// Events rate limiter to limit the max amount of appsec events we can send
	// per second.
	eventsRateLimiter *limiter.TokenTicker
}

// New returns a new AppSec instance if it is enabled with the DD_APPSEC_ENABLED
// env var. An error is returned when AppSec couldn't be started due to
// compilation or configuration errors. When AppSec is not enabled, the returned
// appsec instance is nil, along with a nil error (nil, nil return values).
func newAppSec() (*AppSec, error) {
	// Check if appsec is enabled
	if enabled, _, err := config.IsEnabled(); err != nil {
		return nil, err
	} else if !enabled {
		log.Debug("appsec: security monitoring is not enabled: DD_SERVERLESS_APPSEC_ENABLED is not set to true")
		return nil, nil
	}

	// Check if appsec is used as a standalone product (i.e with APM tracing)
	if config.IsStandalone() {
		log.Info("appsec: starting in standalone mode. APM tracing will be disabled for this service")
	}

	// Check if AppSec can actually run properly
	if err := wafHealth(); err != nil {
		return nil, err
	}

	cfg, err := config.NewConfig()
	if err != nil {
		return nil, err
	}

	var rules map[string]any
	if err := json.Unmarshal(cfg.Rules, &rules); err != nil {
		return nil, err
	}

	handle, err := waf.NewHandle(rules, cfg.Obfuscator.KeyRegex, cfg.Obfuscator.ValueRegex)
	if err != nil {
		return nil, err
	}

	eventsRateLimiter := limiter.NewTokenTicker(int64(cfg.TraceRateLimit), int64(cfg.TraceRateLimit))
	eventsRateLimiter.Start()

	return &AppSec{
		cfg:               cfg,
		handle:            handle,
		eventsRateLimiter: eventsRateLimiter,
	}, nil
}

// Close the AppSec instance.
func (a *AppSec) Close() error {
	a.handle.Close()
	a.eventsRateLimiter.Stop()
	return nil
}

// Monitor runs the security event rules and return the events as a slice
// The monitored addresses are all persistent addresses
//
// This function always returns nil when an error occurs.
func (a *AppSec) Monitor(addresses map[string]any) *httpsec.MonitorResult {
	if a == nil {
		// This needs to be nil-safe so a nil [AppSec] instance is effectvely a no-op [httpsec.Monitorer].
		return nil
	}

	log.Debugf("appsec: monitoring the request context %v", addresses)
	ctx, err := a.handle.NewContextWithBudget(a.cfg.WafTimeout)
	if err != nil {
		log.Errorf("appsec: failed to create waf context: %v", err)
		return nil
	}
	if ctx == nil {
		return nil
	}
	defer ctx.Close()

	// Ask the WAF for schema reporting if API security is enabled
	if a.canExtractSchemas() {
		addresses["waf.context.processor"] = map[string]any{"extract-schema": true}
	}

	res, err := ctx.Run(waf.RunAddressData{Persistent: addresses})
	if err != nil {
		if err == wafErrors.ErrTimeout {
			log.Debugf("appsec: waf timeout value of %s reached", a.cfg.WafTimeout)
		} else {
			log.Errorf("appsec: unexpected waf execution error: %v", err)
			return nil
		}
	}

	stats := ctx.Stats()
	if res.HasEvents() {
		log.Debugf("appsec: security events found in %s: %v", stats.Timers["waf.duration_ext"], res.Events)
	}
	if !a.eventsRateLimiter.Allow() {
		log.Debugf("appsec: security events discarded: the rate limit of %d events/s is reached", a.cfg.TraceRateLimit)
		return nil
	}

	return &httpsec.MonitorResult{
		Result:      res,
		Diagnostics: a.handle.Diagnostics(),
		Stats:       stats,
	}
}

// wafHealth is a simple test helper that returns the same thing as `waf.Health`
// used to return in `go-libddwaf` prior to v1.4.0
func wafHealth() error {
	if ok, err := waf.SupportsTarget(); !ok {
		return err
	}

	if ok, err := waf.Load(); !ok {
		return err
	}
	return nil
}

// canExtractSchemas checks that API Security is enabled
// and that sampling rate allows schema extraction for a specific monitoring instance
func (a *AppSec) canExtractSchemas() bool {
	return a.cfg.APISec.Enabled &&
		//nolint:staticcheck // SA1019 we will migrate to the new APISec sampler at a later point.
		a.cfg.APISec.SampleRate >=
			rand.Float64()
}

func init() {
	appsecLog.SetBackend(appsecLog.Backend{
		Trace:     log.Tracef,
		Debug:     log.Debugf,
		Info:      log.Infof,
		Errorf:    log.Errorf,
		Criticalf: log.Criticalf,
	})
}
