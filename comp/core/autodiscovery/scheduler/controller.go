// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package scheduler

import (
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"

	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/common/types"
	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/status/health"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const schedulersTimeout = 5 * time.Minute

// Controller is a scheduler dispatching to all its registered schedulers
type Controller struct {
	// m protects all fields in this struct.
	m sync.Mutex

	// activeSchedulers is the set of schedulers currently subscribed to configs.
	activeSchedulers map[string]Scheduler

	// scheduledConfigs contains the set of configs that have been scheduled
	// via the schedulerController, but not subsequently unscheduled.
	scheduledConfigs map[Digest]*integration.Config

	// ConfigStateStore contains the desired state of configs
	configStateStore *ConfigStateStore

	// a workqueue to process the config events
	queue workqueue.TypedDelayingInterface[Digest]

	started     bool
	stopChannel chan struct{}

	healthProbe *health.Handle

	// schedulerOperationStartTime is a Unix timestamp that indicates when the
	// last schedule or unschedule operation started. We use a single int since
	// only one worker pulls from the queue, so jobs run one at a time. A value
	// of 0 means that there isn't a scheduling operation ongoing.
	schedulerOperationStartTime *atomic.Int64
}

// NewControllerAndStart inits a scheduler controller without waiting
func NewControllerAndStart() *Controller {
	schedulerController := NewController()
	schedulerController.Start()
	return schedulerController
}

// NewController creates a new controller without starting it
func NewController() *Controller {
	return &Controller{
		scheduledConfigs: make(map[Digest]*integration.Config),
		activeSchedulers: make(map[string]Scheduler),
		// No delay for adding items to the queue first time
		// Add a delay for subsequent retries if check fails
		queue: workqueue.NewTypedDelayingQueueWithConfig(workqueue.TypedDelayingQueueConfig[Digest]{
			Name: "ADSchedulerController",
		}),
		stopChannel:                 make(chan struct{}),
		configStateStore:            NewConfigStateStore(),
		healthProbe:                 health.RegisterLiveness("ad-scheduler-controller"),
		schedulerOperationStartTime: new(atomic.Int64),
	}
}

// Start processing the queue
func (ms *Controller) Start() {
	ms.m.Lock()
	if ms.started {
		return
	}
	ms.started = true
	ms.m.Unlock()
	go ms.healthMonitor()
	go wait.Until(ms.worker, time.Second, ms.stopChannel)
	log.Infof("Autodiscovery scheduler controller started")
}

// Register a new scheduler to receive configurations.
// Previously scheduled configurations that have not subsequently been
// unscheduled can be replayed with the replayConfigs flag.  This replay occurs
// immediately, before the Register call returns.
func (ms *Controller) Register(name string, s Scheduler, replayConfigs bool) {
	ms.m.Lock()
	defer ms.m.Unlock()
	if _, ok := ms.activeSchedulers[name]; ok {
		log.Warnf("Scheduler %s already registered, overriding it", name)
	}
	ms.activeSchedulers[name] = s

	// if replaying configs, replay the currently-scheduled configs; note that
	// this occurs under the protection of `ms.m`, so no config may be double-
	// scheduled or missed in this process.
	if replayConfigs {
		if name == types.CheckCmdName {
			// if the scheduler is the check-cmd, we need to catch up all the
			// configs in configStateStore even if they are not scheduled yet
			// because the caller waitForConfigsFromAD is waiting for the return
			// instead of processing them asynchronously
			configStates := ms.configStateStore.List()
			configs := make([]integration.Config, 0, len(configStates))
			for _, config := range configStates {
				if config.desiredState == Scheduled {
					configs = append(configs, *config.config)
				}
			}
			s.Schedule(configs)
		} else {
			configs := make([]integration.Config, 0, len(ms.scheduledConfigs))
			for _, config := range ms.scheduledConfigs {
				configs = append(configs, *config)
			}
			s.Schedule(configs)
		}
	}
}

// Deregister a scheduler in the schedulerController to dispatch to
func (ms *Controller) Deregister(name string) {
	ms.m.Lock()
	defer ms.m.Unlock()
	if _, ok := ms.activeSchedulers[name]; !ok {
		log.Warnf("Scheduler %s no registered, skipping", name)
		return
	}
	delete(ms.activeSchedulers, name)
}

// ApplyChanges add configDigests to the workqueue
func (ms *Controller) ApplyChanges(changes integration.ConfigChanges) {
	//update desired state immediately
	digests := ms.configStateStore.UpdateDesiredState(changes)
	//add digest to workqueue for processing later
	for _, configDigest := range digests {
		ms.queue.Add(configDigest)
	}
}

func (ms *Controller) worker() {
	for ms.processNextWorkItem() {
	}
}

// processNextWorkItem processes the next work item in the queue
// Action type will be calculated as following:
// Current State,   Desired State     Action
// Unscheduled,     Schedule,         Schedule
// Unscheduled,     Unschedule,       None
// Scheduled,       Schedule,         None
// Scheduled,       Unschedule,       Unschedule
func (ms *Controller) processNextWorkItem() bool {
	configDigest, quit := ms.queue.Get()
	if quit {
		return false
	}
	desiredConfigState, found := ms.configStateStore.GetConfigState(configDigest)
	if !found {
		log.Warnf("config %d not found in configStateStore", configDigest)
		ms.queue.Done(configDigest)
		return true
	}

	currentState := Unscheduled
	desiredState := desiredConfigState.desiredState
	configName := desiredConfigState.config.Name
	if _, found := ms.scheduledConfigs[configDigest]; found {
		currentState = Scheduled
	}
	if desiredState == currentState {
		ms.queue.Done(configDigest)               // no action needed
		ms.configStateStore.Cleanup(configDigest) // cleanup the config state if it is unscheduled already
		return true
	}
	log.Tracef("Controller starts processing config %s: currentState: %d, desiredState: %d", configName, currentState, desiredState)

	// Signal we're starting the schedule/unschedule operations (potential block)
	ms.schedulerOperationStartTime.Store(time.Now().Unix())

	ms.m.Lock() //lock on activeSchedulers
	for _, scheduler := range ms.activeSchedulers {
		if desiredState == Scheduled {
			//to be scheduled
			scheduler.Schedule(([]integration.Config{*desiredConfigState.config})) // TODO: check status of action
		} else {
			//to be unscheduled
			scheduler.Unschedule(([]integration.Config{*desiredConfigState.config})) // TODO: check status of action
		}
	}
	if desiredState == Scheduled {
		// add the config to scheduled
		ms.scheduledConfigs[configDigest] = desiredConfigState.config
	} else {
		delete(ms.scheduledConfigs, configDigest)
		ms.configStateStore.Cleanup(configDigest)
	}
	ms.m.Unlock()

	// Signal we've completed the schedule/unschedule operations
	ms.schedulerOperationStartTime.Store(0)

	ms.queue.Done(configDigest)
	return true
}

// Stop handles clean stop of registered schedulers
func (ms *Controller) Stop() {
	ms.m.Lock()
	defer ms.m.Unlock()

	for _, scheduler := range ms.activeSchedulers {
		scheduler.Stop()
	}

	if err := ms.healthProbe.Deregister(); err != nil {
		log.Errorf("error de-registering health check: %s", err)
	}

	close(ms.stopChannel)
	ms.queue.ShutDown()
	ms.started = false
	ms.scheduledConfigs = make(map[Digest]*integration.Config)
}

func (ms *Controller) healthMonitor() {
	for {
		select {
		case <-ms.healthProbe.C:
			startSec := ms.schedulerOperationStartTime.Load()
			if startSec == 0 {
				// No scheduler operation active
				continue
			}

			// Scheduler operation is currently active. Check if it's blocked.
			startTime := time.Unix(startSec, 0)
			if time.Since(startTime) > schedulersTimeout {
				log.Errorf("Autodiscovery scheduler controller deadlock detected. Scheduler operation has been running for %v", time.Since(startTime))
				return // Stop responding to health checks. This marks the scheduler as unhealthy.
			}
			// Operation is active but not blocked. Continue.

		case <-ms.stopChannel:
			return
		}
	}
}
