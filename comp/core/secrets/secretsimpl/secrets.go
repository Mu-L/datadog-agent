// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package secretsimpl is the implementation for the secrets component
package secretsimpl

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	stdmaps "maps"
	"math/rand"
	"net/http"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/benbjohnson/clock"
	"go.uber.org/fx"
	"golang.org/x/exp/maps"
	yaml "gopkg.in/yaml.v2"

	api "github.com/DataDog/datadog-agent/comp/api/api/def"
	flaretypes "github.com/DataDog/datadog-agent/comp/core/flare/types"
	"github.com/DataDog/datadog-agent/comp/core/secrets"
	"github.com/DataDog/datadog-agent/comp/core/status"
	"github.com/DataDog/datadog-agent/comp/core/telemetry"
	template "github.com/DataDog/datadog-agent/pkg/template/text"
	"github.com/DataDog/datadog-agent/pkg/util/defaultpaths"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/scrubber"
)

const auditFileBasename = "secret-audit-file.json"

var newClock = clock.New

type provides struct {
	fx.Out

	Comp            secrets.Component
	FlareProvider   flaretypes.Provider
	InfoEndpoint    api.AgentEndpointProvider
	RefreshEndpoint api.AgentEndpointProvider
	StatusProvider  status.InformationProvider
}

type dependencies struct {
	fx.In

	Params    secrets.Params
	Telemetry telemetry.Component
}

// Module defines the fx options for this component.
func Module() fxutil.Module {
	return fxutil.Component(
		fx.Provide(newSecretResolverProvider))
}

type secretContext struct {
	// origin is the configuration name where a handle was found
	origin string
	// path is the key associated with the secret in the YAML configuration,
	// represented as a list of field names
	// Example: in this yaml: '{"service": {"token": "ENC[my_token]"}}', ['service', 'token'] is the path and 'my_token' is the handle.
	path []string
}

type handleToContext map[string][]secretContext

type secretResolver struct {
	enabled bool
	lock    sync.Mutex
	cache   map[string]string
	clk     clock.Clock

	// list of handles and where they were found
	origin handleToContext

	backendType             string
	backendConfig           map[string]interface{}
	backendCommand          string
	backendArguments        []string
	backendTimeout          int
	commandAllowGroupExec   bool
	embeddedBackendUsed     bool
	removeTrailingLinebreak bool
	// responseMaxSize defines max size of the JSON output from a secrets reader backend
	responseMaxSize int
	// refresh secrets at a regular interval
	refreshInterval        time.Duration
	refreshIntervalScatter bool
	scatterDuration        time.Duration
	ticker                 *clock.Ticker
	// filename to write audit records to
	auditFilename    string
	auditFileMaxSize int
	auditRotRecs     *rotatingNDRecords
	// subscriptions want to be notified about changes to the secrets
	subscriptions []secrets.SecretChangeCallback

	// can be overridden for testing purposes
	commandHookFunc func(string) ([]byte, error)
	fetchHookFunc   func([]string) (map[string]string, error)
	scrubHookFunc   func([]string)

	// Telemetry
	tlmSecretBackendElapsed telemetry.Gauge
	tlmSecretUnmarshalError telemetry.Counter
	tlmSecretResolveError   telemetry.Counter
}

var _ secrets.Component = (*secretResolver)(nil)

func newEnabledSecretResolver(telemetry telemetry.Component) *secretResolver {
	return &secretResolver{
		cache:                   make(map[string]string),
		origin:                  make(handleToContext),
		enabled:                 true,
		tlmSecretBackendElapsed: telemetry.NewGauge("secret_backend", "elapsed_ms", []string{"command", "exit_code"}, "Elapsed time of secret backend invocation"),
		tlmSecretUnmarshalError: telemetry.NewCounter("secret_backend", "unmarshal_errors_count", []string{}, "Count of errors when unmarshalling the output of the secret binary"),
		tlmSecretResolveError:   telemetry.NewCounter("secret_backend", "resolve_errors_count", []string{"error_kind", "handle"}, "Count of errors when resolving a secret"),
		clk:                     newClock(),
	}
}

func newSecretResolverProvider(deps dependencies) provides {
	resolver := newEnabledSecretResolver(deps.Telemetry)
	resolver.enabled = deps.Params.Enabled
	return provides{
		Comp:            resolver,
		FlareProvider:   flaretypes.NewProvider(resolver.fillFlare),
		InfoEndpoint:    api.NewAgentEndpointProvider(resolver.writeDebugInfo, "/secrets", "GET"),
		RefreshEndpoint: api.NewAgentEndpointProvider(resolver.handleRefresh, "/secret/refresh", "GET"),
		StatusProvider:  status.NewInformationProvider(secretsStatus{resolver: resolver}),
	}
}

// fillFlare add the inventory payload to flares.
func (r *secretResolver) fillFlare(fb flaretypes.FlareBuilder) error {
	var buffer bytes.Buffer
	writer := bufio.NewWriter(&buffer)
	r.GetDebugInfo(writer)
	writer.Flush()
	fb.AddFile("secrets.log", buffer.Bytes()) //nolint:errcheck
	fb.CopyFile(r.auditFilename)              //nolint:errcheck
	return nil
}

func (r *secretResolver) writeDebugInfo(w http.ResponseWriter, _ *http.Request) {
	r.GetDebugInfo(w)
}

func (r *secretResolver) handleRefresh(w http.ResponseWriter, _ *http.Request) {
	result, err := r.Refresh()
	if err != nil {
		setJSONError(w, err, 500)
		return
	}
	w.Write([]byte(result))
}

// setJSONError writes a server error as JSON with the correct http error code
// NOTE: this is copied from comp/api/api/utils to avoid requiring that to be a go module
func setJSONError(w http.ResponseWriter, err error, errorCode int) {
	w.Header().Set("Content-Type", "application/json")
	body, _ := json.Marshal(map[string]string{"error": err.Error()})
	http.Error(w, string(body), errorCode)
}

// assocate with the handle itself the origin (filename) and path where the handle appears
func (r *secretResolver) registerSecretOrigin(handle string, origin string, path []string) {
	for _, info := range r.origin[handle] {
		if info.origin == origin && slices.Equal(info.path, path) {
			// The secret was used twice in the same configuration under the same key: nothing to do
			return
		}
	}

	if len(path) != 0 {
		lastElem := path[len(path)-1:]
		// work around a bug in the scrubber: if the last element looks like an
		// index into a slice, remove it and use the element before
		if _, err := strconv.Atoi(lastElem[0]); err == nil && len(path) >= 2 {
			lastElem = path[len(path)-2 : len(path)-1]
		}
		if r.scrubHookFunc != nil {
			// hook used only for tests
			r.scrubHookFunc(lastElem)
		} else {
			scrubber.AddStrippedKeys(lastElem)
		}
	}

	// clone the path to take ownership of it, otherwise callers may
	// modify the original object and corrupt data in the origin map
	path = slices.Clone(path)

	r.origin[handle] = append(
		r.origin[handle],
		secretContext{
			origin: origin,
			path:   path,
		})
}

// Configure initializes the executable command and other options of the secrets component
func (r *secretResolver) Configure(params secrets.ConfigParams) {
	if !r.enabled {
		return
	}
	r.backendType = params.Type
	r.backendConfig = params.Config
	r.backendCommand = params.Command
	r.embeddedBackendUsed = false
	if r.backendCommand != "" && r.backendType != "" {
		log.Warnf("Both 'secret_backend_command' and 'secret_backend_type' are set, 'secret_backend_type' will be ignored")
	}
	// only use the backend type option if the backend command is not set
	if r.backendType != "" && r.backendCommand == "" {
		if runtime.GOOS == "windows" {
			r.backendCommand = path.Join(defaultpaths.GetInstallPath(), "..", "secret-generic-connector.exe")
		} else {
			r.backendCommand = path.Join(defaultpaths.GetInstallPath(), "..", "..", "embedded", "bin", "secret-generic-connector")
		}
		r.embeddedBackendUsed = true
	}
	r.backendArguments = params.Arguments
	r.backendTimeout = params.Timeout
	if r.backendTimeout == 0 {
		r.backendTimeout = SecretBackendTimeoutDefault
	}
	r.responseMaxSize = params.MaxSize
	if r.responseMaxSize == 0 {
		r.responseMaxSize = SecretBackendOutputMaxSizeDefault
	}

	r.refreshInterval = time.Duration(params.RefreshInterval) * time.Second
	r.refreshIntervalScatter = params.RefreshIntervalScatter
	if r.refreshInterval != 0 {
		r.startRefreshRoutine(nil)
	}

	r.commandAllowGroupExec = params.GroupExecPerm
	r.removeTrailingLinebreak = params.RemoveLinebreak
	if r.commandAllowGroupExec {
		log.Warnf("Agent configuration relax permissions constraint on the secret backend cmd, Group can read and exec")
	}
	r.auditFilename = filepath.Join(params.RunPath, auditFileBasename)
	r.auditFileMaxSize = params.AuditFileMaxSize
	if r.auditFileMaxSize == 0 {
		r.auditFileMaxSize = SecretAuditFileMaxSizeDefault
	}
}

func isEnc(str string) (bool, string) {
	// trimming space and tabs
	str = strings.Trim(str, " 	")
	if strings.HasPrefix(str, "ENC[") && strings.HasSuffix(str, "]") {
		return true, str[4 : len(str)-1]
	}
	return false, ""
}

func (r *secretResolver) startRefreshRoutine(rd *rand.Rand) {
	if r.ticker != nil || r.refreshInterval == 0 {
		return
	}

	if r.refreshIntervalScatter {
		var int63 int64
		if rd == nil {
			int63 = rand.Int63n(int64(r.refreshInterval))
		} else {
			int63 = rd.Int63n(int64(r.refreshInterval))
		}
		// Scatter when the refresh happens within the interval, with a minimum of 1 second
		r.scatterDuration = time.Duration(int63) + time.Second
		log.Infof("first secret refresh will happen in %s", r.scatterDuration)
	} else {
		r.scatterDuration = r.refreshInterval
	}
	r.ticker = r.clk.Ticker(r.scatterDuration)

	go func() {
		<-r.ticker.C
		if _, err := r.Refresh(); err != nil {
			log.Infof("Error with refreshing secrets: %s", err)
		}
		// we want to reset the refresh interval to the refreshInterval after the first refresh in case a scattered first refresh interval was configured
		r.ticker.Reset(r.refreshInterval)

		for {
			<-r.ticker.C
			if _, err := r.Refresh(); err != nil {
				log.Infof("Error with refreshing secrets: %s", err)
			}
		}
	}()
}

// SubscribeToChanges adds this callback to the list that get notified when secrets are resolved or refreshed
func (r *secretResolver) SubscribeToChanges(cb secrets.SecretChangeCallback) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.subscriptions = append(r.subscriptions, cb)
}

// Resolve replaces all encoded secrets in data by executing "secret_backend_command" once if all secrets aren't
// present in the cache.
func (r *secretResolver) Resolve(data []byte, origin string) ([]byte, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if !r.enabled {
		log.Infof("Agent secrets is disabled by caller")
		return nil, nil
	}
	if data == nil || r.backendCommand == "" {
		return data, nil
	}

	var config interface{}
	err := yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("could not Unmarshal config: %s", err)
	}

	// First we collect all new handles in the config
	newHandles := []string{}
	foundSecrets := map[string]struct{}{}

	w := &walker{
		resolver: func(path []string, value string) (string, error) {
			if ok, handle := isEnc(value); ok {
				// Check if we already know this secret
				if secretValue, ok := r.cache[handle]; ok {
					log.Debugf("Secret '%s' was retrieved from cache", handle)
					// keep track of place where a handle was found
					r.registerSecretOrigin(handle, origin, path)
					// notify subscriptions
					for _, sub := range r.subscriptions {
						sub(handle, origin, path, secretValue, secretValue)
					}
					foundSecrets[handle] = struct{}{}
					return secretValue, nil
				}
				// only add handle to newHandles list if it wasn't seen yet
				if _, ok := foundSecrets[handle]; !ok {
					newHandles = append(newHandles, handle)
				}
				foundSecrets[handle] = struct{}{}
				return value, nil
			}
			return value, nil
		},
	}

	if err := w.walk(&config); err != nil {
		return nil, err
	}

	// the configuration does not contain any secrets
	if len(foundSecrets) == 0 {
		return data, nil
	}

	// check if any new secrets need to be fetch
	if len(newHandles) != 0 {
		var secretResponse map[string]string
		var err error
		if r.fetchHookFunc != nil {
			// hook used only for tests
			secretResponse, err = r.fetchHookFunc(newHandles)
		} else {
			secretResponse, err = r.fetchSecret(newHandles)
		}
		if err != nil {
			return nil, err
		}

		w.resolver = func(path []string, value string) (string, error) {
			if ok, handle := isEnc(value); ok {
				if secretValue, ok := secretResponse[handle]; ok {
					log.Debugf("Secret '%s' was successfully resolved", handle)
					// keep track of place where a handle was found
					r.registerSecretOrigin(handle, origin, path)
					return secretValue, nil
				}

				// This should never happen since fetchSecret will return an error if not every handle have
				// been fetched.
				return "", fmt.Errorf("unknown secret '%s'", handle)
			}
			return value, nil
		}

		// Replace all newly resolved secrets in the config
		if err := w.walk(&config); err != nil {
			return nil, err
		}

		// for Resolving secrets, always send notifications
		r.processSecretResponse(secretResponse, false)
	}

	finalConfig, err := yaml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("could not Marshal config after replacing encrypted secrets: %s", err)
	}
	return finalConfig, nil
}

// allowlistPaths restricts what config settings may be updated. Any secrets linked to a settings containing any of the
// following strings will be refreshed.
//
// For example, allowing "additional_endpoints" will trigger notifications for:
//   - "additional_endpoints"
//   - "logs_config.additional_endpoints"
//   - "logs_config.additional_endpoints.url"
//   - ...
//
// NOTE: Related feature to `authorizedConfigPathsCore` in `comp/api/api/def/component.go`
var (
	allowlistPaths = []string{
		"api_key",
		"app_key",
		"additional_endpoints",
		"orchestrator_additional_endpoints",
		"profiling_additional_endpoints",
		"debugger_additional_endpoints",
		"debugger_diagnostics_additional_endpoints",
		"symdb_additional_endpoints",
		"events_additional_endpoints",
	}
	// tests override this to test refresh logic
	allowlistEnabled = true
	allowlistMutex   sync.RWMutex
)

func isAllowlistEnabled() bool {
	allowlistMutex.RLock()
	defer allowlistMutex.RUnlock()
	return allowlistEnabled
}

func setAllowlistEnabled(value bool) {
	allowlistMutex.Lock()
	defer allowlistMutex.Unlock()
	allowlistEnabled = value
}

func secretMatchesAllowlist(secretCtx secretContext) bool {
	if !isAllowlistEnabled() {
		return true
	}
	for _, allowedKey := range allowlistPaths {
		if slices.Contains(secretCtx.path, allowedKey) {
			return true
		}
	}
	return false
}

// matchesAllowlist returns whether the handle is allowed, by matching all setting paths that
// handle appears at against the allowlist
func (r *secretResolver) matchesAllowlist(handle string) bool {
	// if allowlist is disabled, consider every handle a match
	if !isAllowlistEnabled() {
		return true
	}
	return slices.ContainsFunc(r.origin[handle], secretMatchesAllowlist)
}

// for all secrets returned by the backend command, notify subscribers (if allowlist lets them),
// and return the handles that have received new values compared to what was in the cache,
// and where those handles appear
func (r *secretResolver) processSecretResponse(secretResponse map[string]string, useAllowlist bool) secretRefreshInfo {
	var handleInfoList []handleInfo

	// notify subscriptions about the changes to secrets
	for handle, secretValue := range secretResponse {
		oldValue := r.cache[handle]
		// if value hasn't changed, don't send notifications
		if oldValue == secretValue {
			continue
		}

		// if allowlist is enabled and the config setting path is not contained in it, skip it
		if useAllowlist && !r.matchesAllowlist(handle) {
			continue
		}

		log.Debugf("Secret %s has changed", handle)

		places := make([]handlePlace, 0, len(r.origin[handle]))
		for _, secretCtx := range r.origin[handle] {
			for _, sub := range r.subscriptions {
				if useAllowlist && !secretMatchesAllowlist(secretCtx) {
					// only update setting paths that match the allowlist
					continue
				}
				// notify subscribers that secret has changed
				sub(handle, secretCtx.origin, secretCtx.path, oldValue, secretValue)
				secretPath := strings.Join(secretCtx.path, "/")
				places = append(places, handlePlace{Context: secretCtx.origin, Path: secretPath})
			}
		}
		handleInfoList = append(handleInfoList, handleInfo{Name: handle, Places: places})
	}
	// add results to the cache
	stdmaps.Copy(r.cache, secretResponse)
	// return info about the handles sorted by their name
	sort.Slice(handleInfoList, func(i, j int) bool {
		return handleInfoList[i].Name < handleInfoList[j].Name
	})
	return secretRefreshInfo{Handles: handleInfoList}
}

// Refresh the secrets after they have been Resolved by fetching them from the backend again
func (r *secretResolver) Refresh() (string, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	// get handles from the cache that match the allowlist
	newHandles := maps.Keys(r.cache)
	if isAllowlistEnabled() {
		filteredHandles := make([]string, 0, len(newHandles))
		for _, handle := range newHandles {
			if r.matchesAllowlist(handle) {
				filteredHandles = append(filteredHandles, handle)
			}
		}
		newHandles = filteredHandles
	}
	if len(newHandles) == 0 {
		return "", nil
	}

	log.Infof("Refreshing secrets for %d handles", len(newHandles))

	var secretResponse map[string]string
	var err error
	if r.fetchHookFunc != nil {
		// hook used only for tests
		secretResponse, err = r.fetchHookFunc(newHandles)
	} else {
		secretResponse, err = r.fetchSecret(newHandles)
	}
	if err != nil {
		return "", err
	}

	var auditRecordErr error
	// when Refreshing secrets, only update what the allowlist allows by passing `true`
	refreshResult := r.processSecretResponse(secretResponse, true)
	if len(refreshResult.Handles) > 0 {
		// add the results to the audit file, if any secrets have new values
		if err := r.addToAuditFile(secretResponse); err != nil {
			log.Error(err)
			auditRecordErr = err
		}
	}

	// render a report
	t := template.New("secret_refresh")
	t, err = t.Parse(secretRefreshTmpl)
	if err != nil {
		return "", err
	}
	b := new(strings.Builder)
	if err = t.Execute(b, refreshResult); err != nil {
		return "", err
	}
	return b.String(), auditRecordErr
}

type auditRecord struct {
	Handle string `json:"handle"`
	Value  string `json:"value,omitempty"`
}

// addToAuditFile adds records to the audit file based upon newly refreshed secrets
func (r *secretResolver) addToAuditFile(secretResponse map[string]string) error {
	if r.auditFilename == "" {
		return nil
	}
	if r.auditRotRecs == nil {
		r.auditRotRecs = newRotatingNDRecords(r.auditFilename, config{})
	}

	// iterate keys in deterministic order by sorting
	handles := make([]string, 0, len(secretResponse))
	for handle := range secretResponse {
		handles = append(handles, handle)
	}
	sort.Strings(handles)

	var newRows []auditRecord
	// add the newly refreshed secrets to the list of rows
	for _, handle := range handles {
		secretValue := secretResponse[handle]
		scrubbedValue := ""
		if isLikelyAPIOrAppKey(handle, secretValue, r.origin) {
			scrubbedValue = scrubber.HideKeyExceptLastFiveChars(secretValue)
		}
		newRows = append(newRows, auditRecord{Handle: handle, Value: scrubbedValue})
	}

	return r.auditRotRecs.Add(time.Now().UTC(), newRows)
}

var apiKeyStringRegex = regexp.MustCompile(`^[[:xdigit:]]{32}(?:[[:xdigit]]{8})?$`)

// return whether the secret is likely an API key or App key based whether it is 32 or 40 hex
// characters, as well as the setting name where it is found in the config
func isLikelyAPIOrAppKey(handle, secretValue string, origin handleToContext) bool {
	if !apiKeyStringRegex.MatchString(secretValue) {
		return false
	}
	for _, secretCtx := range origin[handle] {
		lastElem := secretCtx.path[len(secretCtx.path)-1]
		if strings.HasSuffix(strings.ToLower(lastElem), "key") {
			return true
		}
	}
	return false
}

type secretInfo struct {
	Executable                   string
	ExecutablePermissions        string
	ExecutablePermissionsDetails interface{}
	ExecutablePermissionsError   string
	Handles                      map[string][][]string
}

type secretRefreshInfo struct {
	Handles []handleInfo
}

type handleInfo struct {
	Name   string
	Places []handlePlace
}

type handlePlace struct {
	Context string
	Path    string
}

//go:embed info.tmpl
var secretInfoTmpl string

//go:embed refresh.tmpl
var secretRefreshTmpl string

// GetDebugInfo exposes debug informations about secrets to be included in a flare
func (r *secretResolver) GetDebugInfo(w io.Writer) {
	if !r.enabled {
		fmt.Fprintf(w, "Agent secrets is disabled by caller\n")
		return
	}
	if r.backendCommand == "" {
		fmt.Fprintf(w, "No secret_backend_command set: secrets feature is not enabled\n")
		return
	}

	t := template.New("secret_info")
	t, err := t.Parse(secretInfoTmpl)
	if err != nil {
		fmt.Fprintf(w, "error parsing secret info template: %s\n", err)
		return
	}

	t, err = t.Parse(permissionsDetailsTemplate)
	if err != nil {
		fmt.Fprintf(w, "error parsing secret permissions details template: %s\n", err)
		return
	}
	permissions := "OK, the executable has the correct permissions"
	if !r.embeddedBackendUsed {
		err = checkRights(r.backendCommand, r.commandAllowGroupExec)
		if err != nil {
			permissions = "error: the executable does not have the correct permissions"
		}
	}

	details, err := r.getExecutablePermissions()
	info := secretInfo{
		Executable:                   r.backendCommand,
		ExecutablePermissions:        permissions,
		ExecutablePermissionsDetails: details,
		Handles:                      map[string][][]string{},
	}
	if err != nil {
		info.ExecutablePermissionsError = err.Error()
	}

	// we sort handles so the output is consistent and testable
	orderedHandles := []string{}
	for handle := range r.origin {
		orderedHandles = append(orderedHandles, handle)
	}
	sort.Strings(orderedHandles)

	for _, handle := range orderedHandles {
		contexts := r.origin[handle]
		details := [][]string{}
		for _, context := range contexts {
			details = append(details, []string{context.origin, strings.Join(context.path, "/")})
		}
		info.Handles[handle] = details
	}

	err = t.Execute(w, info)
	if err != nil {
		fmt.Fprintf(w, "error rendering secret info: %s\n", err)
	}

	fmt.Fprintf(w, "\n")
	if r.refreshInterval > 0 {
		fmt.Fprintf(w, "'secret_refresh_interval' is enabled: the first refresh will happen %s after startup and then every %s\n", r.scatterDuration, r.refreshInterval)
	} else {
		fmt.Fprintf(w, "'secret_refresh_interval' is disabled\n")
	}

}
