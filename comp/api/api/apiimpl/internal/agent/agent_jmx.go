// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package agent implements the api endpoints for the `/agent` prefix.
// This group of endpoints is meant to provide high-level functionalities
// at the agent level.

//go:build jmx

package agent

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/log"

	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/jmxfetch"
	jmxStatus "github.com/DataDog/datadog-agent/pkg/status/jmx"

	yaml "gopkg.in/yaml.v2"
)

func getJMXConfigs(w http.ResponseWriter, r *http.Request) {
	var ts int
	queries := r.URL.Query()
	if timestamps, ok := queries["timestamp"]; ok {
		ts, _ = strconv.Atoi(timestamps[0])
	}

	if int64(ts) > jmxfetch.GetScheduledConfigsModificationTimestamp() {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	log.Debugf("Getting latest JMX Configs as of: %#v", ts)

	j := map[string]interface{}{}
	configs := map[string]integration.JSONMap{}

	for name, config := range jmxfetch.GetScheduledConfigs() {
		var rawInitConfig integration.RawMap
		err := yaml.Unmarshal(config.InitConfig, &rawInitConfig)
		if err != nil {
			log.Errorf("unable to parse JMX configuration: %s", err)
			http.Error(w, err.Error(), 500)
			return
		}

		c := map[string]interface{}{}
		c["init_config"] = jmxfetch.GetJSONSerializableMap(rawInitConfig)
		instances := []integration.JSONMap{}
		for _, instance := range config.Instances {
			var rawInstanceConfig integration.JSONMap
			err := yaml.Unmarshal(instance, &rawInstanceConfig)
			if err != nil {
				log.Errorf("unable to parse JMX configuration: %s", err)
				http.Error(w, err.Error(), 500)
				return
			}
			instances = append(instances, jmxfetch.GetJSONSerializableMap(rawInstanceConfig).(integration.JSONMap))
		}

		c["instances"] = instances
		c["check_name"] = config.Name

		configs[name] = c
	}
	j["configs"] = configs
	j["timestamp"] = time.Now().Unix()
	jsonPayload, err := json.Marshal(jmxfetch.GetJSONSerializableMap(j))
	if err != nil {
		log.Errorf("unable to parse JMX configuration: %s", err)
		http.Error(w, err.Error(), 500)
		return
	}
	_, _ = w.Write(jsonPayload)
}

func setJMXStatus(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)

	var status jmxStatus.Status
	err := decoder.Decode(&status)
	if err != nil {
		log.Errorf("unable to parse jmx status: %s", err)
		http.Error(w, err.Error(), 500)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	jmxStatus.SetStatus(status)
}
