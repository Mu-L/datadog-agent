// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package guiimpl

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/gorilla/mux"
	"go.uber.org/fx"

	api "github.com/DataDog/datadog-agent/comp/api/api/def"
	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/flare"
	guicomp "github.com/DataDog/datadog-agent/comp/core/gui"
	"github.com/DataDog/datadog-agent/comp/core/hostname/hostnameinterface"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	"github.com/DataDog/datadog-agent/comp/core/status"
	"github.com/DataDog/datadog-agent/pkg/api/security"
	template "github.com/DataDog/datadog-agent/pkg/template/html"
	"github.com/DataDog/datadog-agent/pkg/util/defaultpaths"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/DataDog/datadog-agent/pkg/util/option"
	"github.com/DataDog/datadog-agent/pkg/util/system"
)

// Module defines the fx options for this component.
func Module() fxutil.Module {
	return fxutil.Component(
		fx.Provide(newGui),
	)
}

type gui struct {
	logger log.Component

	address  string
	listener net.Listener
	router   *mux.Router

	auth         authenticator
	intentTokens map[string]bool

	// To compute uptime
	startTimestamp int64
}

//go:embed views/templates
var templatesFS embed.FS

// Payload struct is for the JSON messages received from a client POST request
type Payload struct {
	Config string `json:"config"`
	Email  string `json:"email"`
	CaseID string `json:"caseID"`
}

type dependencies struct {
	fx.In

	Log      log.Component
	Config   config.Component
	Flare    flare.Component
	Status   status.Component
	Lc       fx.Lifecycle
	Hostname hostnameinterface.Component
}

type provides struct {
	fx.Out

	Comp     option.Option[guicomp.Component]
	Endpoint api.AgentEndpointProvider
}

// GUI component implementation constructor
// @param deps dependencies needed to construct the gui, bundled in a struct
// @return an optional, depending of "GUI_port" configuration value
func newGui(deps dependencies) provides {

	p := provides{
		Comp: option.None[guicomp.Component](),
	}
	guiPort := deps.Config.GetString("GUI_port")

	if guiPort == "-1" {
		deps.Log.Infof("GUI server port -1 specified: not starting the GUI.")
		return p
	}

	guiHost, err := system.IsLocalAddress(deps.Config.GetString("GUI_host"))
	if err != nil {
		deps.Log.Errorf("GUI server host is not a local address: %s", err)
		return p
	}

	g := gui{
		address:      net.JoinHostPort(guiHost, guiPort),
		logger:       deps.Log,
		intentTokens: make(map[string]bool),
	}

	// Instantiate the gorilla/mux publicRouter
	publicRouter := mux.NewRouter()

	// Fetch the authentication token (persists across sessions)
	authToken, e := security.FetchAuthToken(deps.Config)
	if e != nil {
		g.logger.Error("GUI server initialization failed (unable to get the AuthToken): ", e)
		return p
	}

	sessionExpiration := deps.Config.GetDuration("GUI_session_expiration")
	g.auth = newAuthenticator(authToken, sessionExpiration)

	// register the public routes
	publicRouter.HandleFunc("/", renderIndexPage).Methods("GET")
	publicRouter.HandleFunc("/auth", g.getAccessToken).Methods("GET")
	// Mount our filesystem at the view/{path} route
	publicRouter.PathPrefix("/view/").Handler(http.StripPrefix("/view/", http.HandlerFunc(serveAssets)))

	// Create a subrouter to handle routes that needs authentication
	securedRouter := publicRouter.PathPrefix("/").Subrouter()
	// Set up handlers for the API
	agentRouter := securedRouter.PathPrefix("/agent").Subrouter().StrictSlash(true)
	agentHandler(agentRouter, deps.Flare, deps.Status, deps.Config, deps.Hostname, g.startTimestamp)
	checkRouter := securedRouter.PathPrefix("/checks").Subrouter().StrictSlash(true)
	checkHandler(checkRouter)

	// Check token on every securedRouter endpoints
	securedRouter.Use(g.authMiddleware)

	g.router = publicRouter

	deps.Lc.Append(fx.Hook{
		OnStart: g.start,
		OnStop:  g.stop})

	p.Comp = option.New[guicomp.Component](g)
	p.Endpoint = api.NewAgentEndpointProvider(g.getIntentToken, "/gui/intent", "GET")

	return p
}

// start function is provided to fx as OnStart lifecycle hook, it run the GUI server
func (g *gui) start(_ context.Context) error {
	var e error

	// Set start time...
	g.startTimestamp = time.Now().Unix()

	g.listener, e = net.Listen("tcp", g.address)
	if e != nil {
		g.logger.Error("GUI server didn't achieved to start: ", e)
		return nil
	}
	go http.Serve(g.listener, g.router) //nolint:errcheck
	g.logger.Info("GUI server is listening at " + g.address)
	return nil
}

func (g *gui) stop(_ context.Context) error {
	if g.listener != nil {
		g.listener.Close()
	}
	return nil
}

// Generate a single use IntentToken (32 random chars base64 encoded)
func (g *gui) getIntentToken(w http.ResponseWriter, _ *http.Request) {
	key := make([]byte, 32)
	_, e := rand.Read(key)
	if e != nil {
		http.Error(w, e.Error(), 500)
	}

	token := base64.RawURLEncoding.EncodeToString(key)
	g.intentTokens[token] = true
	w.Write([]byte(token))
}

func renderIndexPage(w http.ResponseWriter, _ *http.Request) {
	data, err := templatesFS.ReadFile("views/templates/index.tmpl")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t, e := template.New("index.tmpl").Parse(string(data))
	if e != nil {
		http.Error(w, e.Error(), http.StatusInternalServerError)
		return
	}

	t, e = t.Parse(instructionTemplate)
	if e != nil {
		http.Error(w, e.Error(), http.StatusInternalServerError)
		return
	}

	e = t.Execute(w, struct {
		RestartEnabled bool
		DocURL         template.URL
	}{
		RestartEnabled: restartEnabled(),
		DocURL:         docURL,
	})
	if e != nil {
		http.Error(w, e.Error(), http.StatusInternalServerError)
		return
	}
}

func serveAssets(w http.ResponseWriter, req *http.Request) {
	staticFilePath := path.Join(defaultpaths.GetDistPath(), "views")

	// checking against path traversal
	path, err := securejoin.SecureJoin(staticFilePath, req.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	ctype := mime.TypeByExtension(filepath.Ext(path))
	if ctype == "" {
		ctype = http.DetectContentType(data)
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}

func (g *gui) getAccessToken(w http.ResponseWriter, r *http.Request) {

	// intentToken is present in the query when the GUI is opened from the CLI
	intentToken := r.URL.Query().Get("intent")
	if intentToken == "" {
		w.WriteHeader(http.StatusUnauthorized)
		http.Error(w, "missing intentToken", 401)
		return
	}
	if _, ok := g.intentTokens[intentToken]; !ok {
		w.WriteHeader(http.StatusUnauthorized)
		http.Error(w, "invalid intentToken", 401)
		return
	}

	// Remove single use token from map
	delete(g.intentTokens, intentToken)

	// generate accessToken
	accessToken := g.auth.GenerateAccessToken()

	// set the accessToken as a cookie and redirect the user to root page
	http.SetCookie(w, &http.Cookie{
		Name:     "accessToken",
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   31536000, // 1 year
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// Middleware which blocks access to secured files from unauthorized clients
func (g *gui) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Disable caching
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

		cookie, _ := r.Cookie("accessToken")
		if cookie == nil {
			http.Error(w, "missing accessToken", http.StatusUnauthorized)
			return
		}

		// check accessToken is valid (same key, same sessionId)
		err := g.auth.ValidateToken(cookie.Value)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Token was valid: serve the requested resource
		next.ServeHTTP(w, r)
	})
}

// Helper function which unmarshals a POST requests data into a Payload object
func parseBody(r *http.Request) (Payload, error) {
	var p Payload
	body, e := io.ReadAll(r.Body)
	if e != nil {
		return p, e
	}

	e = json.Unmarshal(body, &p)
	if e != nil {
		return p, e
	}

	return p, nil
}
