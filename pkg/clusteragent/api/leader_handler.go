// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver

// Package api contains the telemetry of the Cluster Agent API and implements
// the forwarding of queries from Cluster Agent followers to the leader.
package api

import (
	"net/http"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/apiserver/leaderelection"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// LeaderHandler forwards queries to the leader if we are a follower
type LeaderHandler struct {
	leaderforwarder       *LeaderForwarder
	le                    *leaderelection.LeaderEngine
	leaderElectionEnabled bool
}

// NewLeaderHandler returns a new LeaderHandler
func NewLeaderHandler(lf *LeaderForwarder) *LeaderHandler {
	leaderEngine, _ := leaderelection.GetLeaderEngine()

	return &LeaderHandler{leaderforwarder: lf, le: leaderEngine, leaderElectionEnabled: config.Datadog.GetBool("leader_election")}
}

// RejectOrForwardLeaderQuery performs some checks on incoming queries that should go to a leader:
// - Forward to leader if we are a follower
// - Reject with "not ready" if leader election status is unknown
func (h *LeaderHandler) RejectOrForwardLeaderQuery(rw http.ResponseWriter, req *http.Request) bool {
	if h.le == nil {
		leaderEngine, err := leaderelection.GetLeaderEngine()
		if err != nil {
			log.Errorf("Leader election is not initialized: %v", err)
			http.Error(rw, "Leader election is not initialized", http.StatusServiceUnavailable)
			return true
		}
		h.le = leaderEngine
	}

	if h.le.IsLeader() || !h.leaderElectionEnabled {
		return false
	}

	ip, err := h.le.GetLeaderIP()
	if err != nil {
		log.Errorf("Failed to retrieve leader ip: %v", err)
		http.Error(rw, "Failed to retrieve leader ip", http.StatusServiceUnavailable)
		return true
	}

	h.leaderforwarder.SetLeaderIP(isp)
	h.leaderforwarder.Forward(rw, req)
	return true
}
