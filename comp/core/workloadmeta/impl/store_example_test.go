// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package workloadmeta

import (
	"fmt"
	"testing"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/core/config"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	logmock "github.com/DataDog/datadog-agent/comp/core/log/mock"
	wmdef "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

func TestExampleStoreSubscribe(t *testing.T) {

	deps := fxutil.Test[dependencies](t, fx.Options(
		fx.Provide(func() log.Component { return logmock.New(t) }),
		config.MockModule(),
		fx.Supply(wmdef.NewParams()),
	))

	s := newWorkloadmetaObject(deps)

	filter := wmdef.NewFilterBuilder().SetSource(wmdef.SourceRuntime).AddKind(wmdef.KindContainer).Build()
	ch := s.Subscribe("test", wmdef.NormalPriority, filter)

	go func() {
		for bundle := range ch {
			// close Ch to indicate that the Store can proceed to the next subscriber
			bundle.Acknowledge()

			for _, evt := range bundle.Events {
				if evt.Type == wmdef.EventTypeSet {
					fmt.Printf("new/updated container: %s\n", evt.Entity.GetID().ID)
				} else {
					fmt.Printf("container removed: %s\n", evt.Entity.GetID().ID)
				}
			}
		}
	}()

	// unsubscribe immediately so that this example does not hang
	s.Unsubscribe(ch)

	// Output:
}