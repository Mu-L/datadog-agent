// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

//go:build kubeapiserver

package v1

import (
	"io"
	"net/http"

	"github.com/DataDog/datadog-agent/pkg/clusteragent/api"
	"github.com/DataDog/datadog-agent/pkg/clusteragent/languagedetection"
	"github.com/DataDog/datadog-agent/pkg/config"
	pbgo "github.com/DataDog/datadog-agent/pkg/proto/pbgo/process"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/apiserver/leaderelection"

	"github.com/gorilla/mux"
	"google.golang.org/protobuf/proto"
)

// InstallLanguageDetectionEndpoints installs language detection endpoints
func InstallLanguageDetectionEndpoints(r *mux.Router) error {
	lf := api.NewLeaderForwarder(config.Datadog.GetInt("cluster_agent.cmd_port"), config.Datadog.GetInt("cluster_agent.max_leader_connections"))
	handler, err := newHandler(lf)
	if err != nil {
		return err
	}

	r.HandleFunc("/languagedetection", api.WithTelemetryWrapper("postDetectedLanguages", handler.postDetectedLanguages)).Methods("POST")
	return nil
}

type handler struct {
	leaderforwarder       *api.LeaderForwarder
	le                    *leaderelection.LeaderEngine
	leaderElectionEnabled bool
}

// newHandler returns a new handler
func newHandler(lf *api.LeaderForwarder) (*handler, error) {
	leaderEngine, err := leaderelection.GetLeaderEngine()
	if err != nil {
		return nil, err
	}

	return &handler{leaderforwarder: lf, le: leaderEngine, leaderElectionEnabled: config.Datadog.GetBool("leader_election")}, nil
}

// rejectOrForwardLeaderQuery performs some checks on incoming queries that should go to a leader:
// - Forward to leader if we are a follower
// - Reject with "not ready" if leader election status is unknown
func (h *handler) rejectOrForwardLeaderQuery(rw http.ResponseWriter, req *http.Request) bool {
	if h.le.IsLeader() || !h.leaderElectionEnabled {
		return false
	}

	ip, err := h.le.GetLeaderIP()
	if err != nil {
		http.Error(rw, "Follower unable to forward as leaderForwarder is not available yet", http.StatusServiceUnavailable)
		return true
	}

	h.leaderforwarder.SetLeaderIP(ip)
	h.leaderforwarder.Forward(rw, req)
	return true
}

func (h *handler) postDetectedLanguages(w http.ResponseWriter, r *http.Request) {
	if !config.Datadog.GetBool("language_detection.enabled") {
		languagedetection.ErrorResponses.Inc()
		http.Error(w, "Language detection feature is disabled on the cluster agent", http.StatusServiceUnavailable)
		return
	}

	// Reject if not leader
	if h.rejectOrForwardLeaderQuery(w, r) {
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		languagedetection.ErrorResponses.Inc()
		return
	}

	// Create a new instance of the protobuf message type
	requestData := &pbgo.ParentLanguageAnnotationRequest{}

	// Unmarshal the request body into the protobuf message
	err = proto.Unmarshal(body, requestData)
	if err != nil {
		http.Error(w, "Failed to unmarshal request body", http.StatusBadRequest)
		languagedetection.ErrorResponses.Inc()
		return
	}

	lp, err := languagedetection.NewLanguagePatcher()
	if err != nil {
		http.Error(w, "Failed to get k8s apiserver client", http.StatusInternalServerError)
		languagedetection.ErrorResponses.Inc()
		return
	}

	// Answer before patching
	languagedetection.OkResponses.Inc()
	w.WriteHeader(http.StatusOK)

	// Patch annotations to deployments
	lp.PatchAllOwners(requestData)
}
