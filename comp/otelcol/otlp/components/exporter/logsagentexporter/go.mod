module github.com/DataDog/datadog-agent/comp/otelcol/otlp/components/exporter/logsagentexporter

go 1.23.0

require (
	github.com/DataDog/datadog-agent/comp/logs/agent/config v0.61.0
	github.com/DataDog/datadog-agent/comp/otelcol/otlp/testutil v0.57.0-devel.0.20240718200853-81bf3b2e412d
	github.com/DataDog/datadog-agent/pkg/logs/message v0.61.0
	github.com/DataDog/datadog-agent/pkg/logs/sources v0.61.0
	github.com/DataDog/datadog-agent/pkg/util/otel v0.64.0
	github.com/DataDog/datadog-agent/pkg/util/scrubber v0.64.1
	github.com/DataDog/opentelemetry-mapping-go/pkg/otlp/attributes v0.29.1
	github.com/DataDog/opentelemetry-mapping-go/pkg/otlp/logs v0.29.0
	github.com/stormcat24/protodep v0.1.8
	github.com/stretchr/testify v1.10.0
	go.opentelemetry.io/collector/component v1.37.0
	go.opentelemetry.io/collector/config/configretry v1.37.0
	go.opentelemetry.io/collector/exporter v0.131.0
	go.opentelemetry.io/collector/exporter/exportertest v0.131.0
	go.opentelemetry.io/collector/pdata v1.37.0
)

require (
	go.opentelemetry.io/collector/client v1.37.0 // indirect
	go.opentelemetry.io/collector/pdata/xpdata v0.131.0 // indirect
)

require (
	github.com/cenkalti/backoff/v5 v5.0.2 // indirect
	go.opentelemetry.io/collector/internal/telemetry v0.131.0 // indirect
	go.opentelemetry.io/contrib/bridges/otelzap v0.12.0 // indirect
	go.opentelemetry.io/otel/log v0.13.0 // indirect
)

require (
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/knadh/koanf/maps v0.1.2 // indirect
	github.com/knadh/koanf/providers/confmap v1.0.0 // indirect
	github.com/knadh/koanf/v2 v2.2.2 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	go.opentelemetry.io/collector/config/configoptional v0.131.0 // indirect
	go.opentelemetry.io/collector/confmap v1.37.0 // indirect
	go.opentelemetry.io/collector/consumer/xconsumer v0.131.0 // indirect
	go.opentelemetry.io/collector/exporter/xexporter v0.131.0 // indirect
	go.opentelemetry.io/collector/extension/xextension v0.131.0 // indirect
	go.opentelemetry.io/collector/receiver/xreceiver v0.131.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
)

require (
	github.com/hashicorp/go-version v1.7.0 // indirect
	go.opentelemetry.io/collector/component/componenttest v0.131.0 // indirect
	go.opentelemetry.io/collector/consumer/consumererror v0.131.0 // indirect
	go.opentelemetry.io/collector/featuregate v1.37.0 // indirect
	go.opentelemetry.io/collector/receiver/receivertest v0.131.0 // indirect
)

require (
	github.com/DataDog/datadog-agent/comp/core/secrets v0.61.0 // indirect
	github.com/DataDog/datadog-agent/comp/core/tagger/types v0.67.0 // indirect
	github.com/DataDog/datadog-agent/comp/core/tagger/utils v0.60.0 // indirect
	github.com/DataDog/datadog-agent/pkg/collector/check/defaults v0.61.0 // indirect
	github.com/DataDog/datadog-agent/pkg/config/create v0.0.0-00010101000000-000000000000 // indirect
	github.com/DataDog/datadog-agent/pkg/config/env v0.61.0 // indirect
	github.com/DataDog/datadog-agent/pkg/config/mock v0.61.0 // indirect
	github.com/DataDog/datadog-agent/pkg/config/model v0.64.1 // indirect
	github.com/DataDog/datadog-agent/pkg/config/nodetreemodel v0.64.1 // indirect
	github.com/DataDog/datadog-agent/pkg/config/setup v0.61.0 // indirect
	github.com/DataDog/datadog-agent/pkg/config/structure v0.61.0 // indirect
	github.com/DataDog/datadog-agent/pkg/config/teeconfig v0.64.1 // indirect
	github.com/DataDog/datadog-agent/pkg/config/utils v0.61.0 // indirect
	github.com/DataDog/datadog-agent/pkg/config/viperconfig v0.64.1 // indirect
	github.com/DataDog/datadog-agent/pkg/fips v0.0.0 // indirect
	github.com/DataDog/datadog-agent/pkg/logs/status/utils v0.61.0 // indirect
	github.com/DataDog/datadog-agent/pkg/proto v0.64.0-devel // indirect
	github.com/DataDog/datadog-agent/pkg/util/executable v0.61.0 // indirect
	github.com/DataDog/datadog-agent/pkg/util/filesystem v0.61.0 // indirect
	github.com/DataDog/datadog-agent/pkg/util/hostname/validate v0.61.0 // indirect
	github.com/DataDog/datadog-agent/pkg/util/log v0.64.1 // indirect
	github.com/DataDog/datadog-agent/pkg/util/option v0.64.0-devel // indirect
	github.com/DataDog/datadog-agent/pkg/util/pointer v0.61.0 // indirect
	github.com/DataDog/datadog-agent/pkg/util/statstracker v0.61.0 // indirect
	github.com/DataDog/datadog-agent/pkg/util/system v0.61.0 // indirect
	github.com/DataDog/datadog-agent/pkg/util/system/socket v0.61.0 // indirect
	github.com/DataDog/datadog-agent/pkg/util/winutil v0.61.0 // indirect
	github.com/DataDog/datadog-agent/pkg/version v0.64.1 // indirect
	github.com/DataDog/datadog-api-client-go/v2 v2.42.0 // indirect
	github.com/DataDog/opentelemetry-mapping-go/pkg/inframetadata v0.29.1 // indirect
	github.com/DataDog/sketches-go v1.4.7 // indirect
	github.com/DataDog/viper v1.14.1-0.20250612143030-1b15c8822ed4 // indirect
	github.com/DataDog/zstd v1.5.6 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/briandowns/spinner v1.23.0 // indirect
	github.com/cihub/seelog v0.0.0-20170130134532-f561c5e57575 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/ebitengine/purego v0.8.4 // indirect
	github.com/fatih/color v1.18.0 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/gofrs/flock v0.12.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/hcl v1.0.1-vault-7 // indirect
	github.com/hectane/go-acl v0.0.0-20230122075934-ca0b05cb1adb // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/lufia/plan9stats v0.0.0-20240909124753-873cd0166683 // indirect
	github.com/magiconair/properties v1.8.10 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/mapstructure v1.5.1-0.20231216201459-8508981c8b6c // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/philhofer/fwd v1.1.3-0.20240916144458-20a13a1f6b7c // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/shirou/gopsutil/v4 v4.25.6 // indirect
	github.com/spf13/afero v1.14.0 // indirect
	github.com/spf13/cast v1.9.2 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/tinylib/msgp v1.3.0 // indirect
	github.com/tklauser/go-sysconf v0.3.15 // indirect
	github.com/tklauser/numcpus v0.10.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/collector/consumer v1.37.0 // indirect
	go.opentelemetry.io/collector/consumer/consumertest v0.131.0 // indirect
	go.opentelemetry.io/collector/extension v1.37.0 // indirect
	go.opentelemetry.io/collector/pdata/pprofile v0.131.0 // indirect
	go.opentelemetry.io/collector/pipeline v0.131.0 // indirect
	go.opentelemetry.io/collector/receiver v1.37.0 // indirect
	go.opentelemetry.io/otel v1.37.0 // indirect
	go.opentelemetry.io/otel/metric v1.37.0 // indirect
	go.opentelemetry.io/otel/sdk v1.37.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.37.0 // indirect
	go.opentelemetry.io/otel/trace v1.37.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/exp v0.0.0-20250718183923-645b1fa84792 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/oauth2 v0.30.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/term v0.33.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	golang.org/x/time v0.12.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250603155806-513f23925822 // indirect
	google.golang.org/grpc v1.74.2 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// This section was automatically added by 'dda inv modules.add-all-replace' command, do not edit manually

replace (
	github.com/DataDog/datadog-agent/comp/api/api/def => ../../../../../../comp/api/api/def
	github.com/DataDog/datadog-agent/comp/core/config => ../../../../../../comp/core/config
	github.com/DataDog/datadog-agent/comp/core/configsync => ../../../../../../comp/core/configsync
	github.com/DataDog/datadog-agent/comp/core/flare/builder => ../../../../../../comp/core/flare/builder
	github.com/DataDog/datadog-agent/comp/core/flare/types => ../../../../../../comp/core/flare/types
	github.com/DataDog/datadog-agent/comp/core/hostname/hostnameinterface => ../../../../../../comp/core/hostname/hostnameinterface
	github.com/DataDog/datadog-agent/comp/core/ipc/def => ../../../../../../comp/core/ipc/def
	github.com/DataDog/datadog-agent/comp/core/ipc/httphelpers => ../../../../../../comp/core/ipc/httphelpers
	github.com/DataDog/datadog-agent/comp/core/ipc/impl => ../../../../../../comp/core/ipc/impl
	github.com/DataDog/datadog-agent/comp/core/ipc/mock => ../../../../../../comp/core/ipc/mock
	github.com/DataDog/datadog-agent/comp/core/log/def => ../../../../../../comp/core/log/def
	github.com/DataDog/datadog-agent/comp/core/log/fx => ../../../../../../comp/core/log/fx
	github.com/DataDog/datadog-agent/comp/core/log/impl => ../../../../../../comp/core/log/impl
	github.com/DataDog/datadog-agent/comp/core/log/impl-trace => ../../../../../../comp/core/log/impl-trace
	github.com/DataDog/datadog-agent/comp/core/log/mock => ../../../../../../comp/core/log/mock
	github.com/DataDog/datadog-agent/comp/core/secrets => ../../../../../../comp/core/secrets
	github.com/DataDog/datadog-agent/comp/core/status => ../../../../../../comp/core/status
	github.com/DataDog/datadog-agent/comp/core/status/statusimpl => ../../../../../../comp/core/status/statusimpl
	github.com/DataDog/datadog-agent/comp/core/tagger/def => ../../../../../../comp/core/tagger/def
	github.com/DataDog/datadog-agent/comp/core/tagger/fx-remote => ../../../../../../comp/core/tagger/fx-remote
	github.com/DataDog/datadog-agent/comp/core/tagger/generic_store => ../../../../../../comp/core/tagger/generic_store
	github.com/DataDog/datadog-agent/comp/core/tagger/impl-remote => ../../../../../../comp/core/tagger/impl-remote
	github.com/DataDog/datadog-agent/comp/core/tagger/origindetection => ../../../../../../comp/core/tagger/origindetection
	github.com/DataDog/datadog-agent/comp/core/tagger/subscriber => ../../../../../../comp/core/tagger/subscriber
	github.com/DataDog/datadog-agent/comp/core/tagger/tags => ../../../../../../comp/core/tagger/tags
	github.com/DataDog/datadog-agent/comp/core/tagger/telemetry => ../../../../../../comp/core/tagger/telemetry
	github.com/DataDog/datadog-agent/comp/core/tagger/types => ../../../../../../comp/core/tagger/types
	github.com/DataDog/datadog-agent/comp/core/tagger/utils => ../../../../../../comp/core/tagger/utils
	github.com/DataDog/datadog-agent/comp/core/telemetry => ../../../../../../comp/core/telemetry
	github.com/DataDog/datadog-agent/comp/def => ../../../../../../comp/def
	github.com/DataDog/datadog-agent/comp/forwarder/defaultforwarder => ../../../../../../comp/forwarder/defaultforwarder
	github.com/DataDog/datadog-agent/comp/forwarder/orchestrator/orchestratorinterface => ../../../../../../comp/forwarder/orchestrator/orchestratorinterface
	github.com/DataDog/datadog-agent/comp/logs/agent/config => ../../../../../../comp/logs/agent/config
	github.com/DataDog/datadog-agent/comp/netflow/payload => ../../../../../../comp/netflow/payload
	github.com/DataDog/datadog-agent/comp/otelcol/collector-contrib/def => ../../../../../../comp/otelcol/collector-contrib/def
	github.com/DataDog/datadog-agent/comp/otelcol/collector-contrib/impl => ../../../../../../comp/otelcol/collector-contrib/impl
	github.com/DataDog/datadog-agent/comp/otelcol/converter/def => ../../../../../../comp/otelcol/converter/def
	github.com/DataDog/datadog-agent/comp/otelcol/converter/impl => ../../../../../../comp/otelcol/converter/impl
	github.com/DataDog/datadog-agent/comp/otelcol/ddflareextension/def => ../../../../../../comp/otelcol/ddflareextension/def
	github.com/DataDog/datadog-agent/comp/otelcol/ddflareextension/impl => ../../../../../../comp/otelcol/ddflareextension/impl
	github.com/DataDog/datadog-agent/comp/otelcol/ddflareextension/types => ../../../../../../comp/otelcol/ddflareextension/types
	github.com/DataDog/datadog-agent/comp/otelcol/ddprofilingextension/def => ../../../../../../comp/otelcol/ddprofilingextension/def
	github.com/DataDog/datadog-agent/comp/otelcol/ddprofilingextension/impl => ../../../../../../comp/otelcol/ddprofilingextension/impl
	github.com/DataDog/datadog-agent/comp/otelcol/logsagentpipeline => ../../../../../../comp/otelcol/logsagentpipeline
	github.com/DataDog/datadog-agent/comp/otelcol/logsagentpipeline/logsagentpipelineimpl => ../../../../../../comp/otelcol/logsagentpipeline/logsagentpipelineimpl
	github.com/DataDog/datadog-agent/comp/otelcol/otlp/components/connector/datadogconnector => ../../../../../../comp/otelcol/otlp/components/connector/datadogconnector
	github.com/DataDog/datadog-agent/comp/otelcol/otlp/components/exporter/datadogexporter => ../../../../../../comp/otelcol/otlp/components/exporter/datadogexporter
	github.com/DataDog/datadog-agent/comp/otelcol/otlp/components/exporter/serializerexporter => ../../../../../../comp/otelcol/otlp/components/exporter/serializerexporter
	github.com/DataDog/datadog-agent/comp/otelcol/otlp/components/metricsclient => ../../../../../../comp/otelcol/otlp/components/metricsclient
	github.com/DataDog/datadog-agent/comp/otelcol/otlp/components/processor/infraattributesprocessor => ../../../../../../comp/otelcol/otlp/components/processor/infraattributesprocessor
	github.com/DataDog/datadog-agent/comp/otelcol/otlp/components/statsprocessor => ../../../../../../comp/otelcol/otlp/components/statsprocessor
	github.com/DataDog/datadog-agent/comp/otelcol/otlp/testutil => ../../../../../../comp/otelcol/otlp/testutil
	github.com/DataDog/datadog-agent/comp/otelcol/status/def => ../../../../../../comp/otelcol/status/def
	github.com/DataDog/datadog-agent/comp/otelcol/status/impl => ../../../../../../comp/otelcol/status/impl
	github.com/DataDog/datadog-agent/comp/serializer/logscompression => ../../../../../../comp/serializer/logscompression
	github.com/DataDog/datadog-agent/comp/serializer/metricscompression => ../../../../../../comp/serializer/metricscompression
	github.com/DataDog/datadog-agent/comp/trace/agent/def => ../../../../../../comp/trace/agent/def
	github.com/DataDog/datadog-agent/comp/trace/compression/def => ../../../../../../comp/trace/compression/def
	github.com/DataDog/datadog-agent/comp/trace/compression/impl-gzip => ../../../../../../comp/trace/compression/impl-gzip
	github.com/DataDog/datadog-agent/comp/trace/compression/impl-zstd => ../../../../../../comp/trace/compression/impl-zstd
	github.com/DataDog/datadog-agent/pkg/aggregator/ckey => ../../../../../../pkg/aggregator/ckey
	github.com/DataDog/datadog-agent/pkg/api => ../../../../../../pkg/api
	github.com/DataDog/datadog-agent/pkg/collector/check/defaults => ../../../../../../pkg/collector/check/defaults
	github.com/DataDog/datadog-agent/pkg/config/create => ../../../../../../pkg/config/create
	github.com/DataDog/datadog-agent/pkg/config/env => ../../../../../../pkg/config/env
	github.com/DataDog/datadog-agent/pkg/config/mock => ../../../../../../pkg/config/mock
	github.com/DataDog/datadog-agent/pkg/config/model => ../../../../../../pkg/config/model
	github.com/DataDog/datadog-agent/pkg/config/nodetreemodel => ../../../../../../pkg/config/nodetreemodel
	github.com/DataDog/datadog-agent/pkg/config/remote => ../../../../../../pkg/config/remote
	github.com/DataDog/datadog-agent/pkg/config/setup => ../../../../../../pkg/config/setup
	github.com/DataDog/datadog-agent/pkg/config/structure => ../../../../../../pkg/config/structure
	github.com/DataDog/datadog-agent/pkg/config/teeconfig => ../../../../../../pkg/config/teeconfig
	github.com/DataDog/datadog-agent/pkg/config/utils => ../../../../../../pkg/config/utils
	github.com/DataDog/datadog-agent/pkg/config/viperconfig => ../../../../../../pkg/config/viperconfig
	github.com/DataDog/datadog-agent/pkg/errors => ../../../../../../pkg/errors
	github.com/DataDog/datadog-agent/pkg/fips => ../../../../../../pkg/fips
	github.com/DataDog/datadog-agent/pkg/fleet/installer => ../../../../../../pkg/fleet/installer
	github.com/DataDog/datadog-agent/pkg/gohai => ../../../../../../pkg/gohai
	github.com/DataDog/datadog-agent/pkg/linters/components/pkgconfigusage => ../../../../../../pkg/linters/components/pkgconfigusage
	github.com/DataDog/datadog-agent/pkg/logs/client => ../../../../../../pkg/logs/client
	github.com/DataDog/datadog-agent/pkg/logs/diagnostic => ../../../../../../pkg/logs/diagnostic
	github.com/DataDog/datadog-agent/pkg/logs/message => ../../../../../../pkg/logs/message
	github.com/DataDog/datadog-agent/pkg/logs/metrics => ../../../../../../pkg/logs/metrics
	github.com/DataDog/datadog-agent/pkg/logs/pipeline => ../../../../../../pkg/logs/pipeline
	github.com/DataDog/datadog-agent/pkg/logs/processor => ../../../../../../pkg/logs/processor
	github.com/DataDog/datadog-agent/pkg/logs/sds => ../../../../../../pkg/logs/sds
	github.com/DataDog/datadog-agent/pkg/logs/sender => ../../../../../../pkg/logs/sender
	github.com/DataDog/datadog-agent/pkg/logs/sources => ../../../../../../pkg/logs/sources
	github.com/DataDog/datadog-agent/pkg/logs/status/statusinterface => ../../../../../../pkg/logs/status/statusinterface
	github.com/DataDog/datadog-agent/pkg/logs/status/utils => ../../../../../../pkg/logs/status/utils
	github.com/DataDog/datadog-agent/pkg/logs/util/testutils => ../../../../../../pkg/logs/util/testutils
	github.com/DataDog/datadog-agent/pkg/metrics => ../../../../../../pkg/metrics
	github.com/DataDog/datadog-agent/pkg/network/payload => ../../../../../../pkg/network/payload
	github.com/DataDog/datadog-agent/pkg/networkdevice/profile => ../../../../../../pkg/networkdevice/profile
	github.com/DataDog/datadog-agent/pkg/networkpath/payload => ../../../../../../pkg/networkpath/payload
	github.com/DataDog/datadog-agent/pkg/obfuscate => ../../../../../../pkg/obfuscate
	github.com/DataDog/datadog-agent/pkg/opentelemetry-mapping-go/inframetadata => ../../../../../../pkg/opentelemetry-mapping-go/inframetadata
	github.com/DataDog/datadog-agent/pkg/opentelemetry-mapping-go/inframetadata/gohai/internal/gohaitest => ../../../../../../pkg/opentelemetry-mapping-go/inframetadata/gohai/internal/gohaitest
	github.com/DataDog/datadog-agent/pkg/opentelemetry-mapping-go/otlp/attributes => ../../../../../../pkg/opentelemetry-mapping-go/otlp/attributes
	github.com/DataDog/datadog-agent/pkg/opentelemetry-mapping-go/otlp/logs => ../../../../../../pkg/opentelemetry-mapping-go/otlp/logs
	github.com/DataDog/datadog-agent/pkg/opentelemetry-mapping-go/otlp/metrics => ../../../../../../pkg/opentelemetry-mapping-go/otlp/metrics
	github.com/DataDog/datadog-agent/pkg/orchestrator/model => ../../../../../../pkg/orchestrator/model
	github.com/DataDog/datadog-agent/pkg/process/util/api => ../../../../../../pkg/process/util/api
	github.com/DataDog/datadog-agent/pkg/proto => ../../../../../../pkg/proto
	github.com/DataDog/datadog-agent/pkg/remoteconfig/state => ../../../../../../pkg/remoteconfig/state
	github.com/DataDog/datadog-agent/pkg/security/secl => ../../../../../../pkg/security/secl
	github.com/DataDog/datadog-agent/pkg/security/seclwin => ../../../../../../pkg/security/seclwin
	github.com/DataDog/datadog-agent/pkg/serializer => ../../../../../../pkg/serializer
	github.com/DataDog/datadog-agent/pkg/status/health => ../../../../../../pkg/status/health
	github.com/DataDog/datadog-agent/pkg/tagger/types => ../../../../../../pkg/tagger/types
	github.com/DataDog/datadog-agent/pkg/tagset => ../../../../../../pkg/tagset
	github.com/DataDog/datadog-agent/pkg/telemetry => ../../../../../../pkg/telemetry
	github.com/DataDog/datadog-agent/pkg/template => ../../../../../../pkg/template
	github.com/DataDog/datadog-agent/pkg/trace => ../../../../../../pkg/trace
	github.com/DataDog/datadog-agent/pkg/trace/stats/oteltest => ../../../../../../pkg/trace/stats/oteltest
	github.com/DataDog/datadog-agent/pkg/util/backoff => ../../../../../../pkg/util/backoff
	github.com/DataDog/datadog-agent/pkg/util/buf => ../../../../../../pkg/util/buf
	github.com/DataDog/datadog-agent/pkg/util/cache => ../../../../../../pkg/util/cache
	github.com/DataDog/datadog-agent/pkg/util/cgroups => ../../../../../../pkg/util/cgroups
	github.com/DataDog/datadog-agent/pkg/util/common => ../../../../../../pkg/util/common
	github.com/DataDog/datadog-agent/pkg/util/compression => ../../../../../../pkg/util/compression
	github.com/DataDog/datadog-agent/pkg/util/containers/image => ../../../../../../pkg/util/containers/image
	github.com/DataDog/datadog-agent/pkg/util/defaultpaths => ../../../../../../pkg/util/defaultpaths
	github.com/DataDog/datadog-agent/pkg/util/executable => ../../../../../../pkg/util/executable
	github.com/DataDog/datadog-agent/pkg/util/filesystem => ../../../../../../pkg/util/filesystem
	github.com/DataDog/datadog-agent/pkg/util/flavor => ../../../../../../pkg/util/flavor
	github.com/DataDog/datadog-agent/pkg/util/fxutil => ../../../../../../pkg/util/fxutil
	github.com/DataDog/datadog-agent/pkg/util/grpc => ../../../../../../pkg/util/grpc
	github.com/DataDog/datadog-agent/pkg/util/hostname/validate => ../../../../../../pkg/util/hostname/validate
	github.com/DataDog/datadog-agent/pkg/util/http => ../../../../../../pkg/util/http
	github.com/DataDog/datadog-agent/pkg/util/json => ../../../../../../pkg/util/json
	github.com/DataDog/datadog-agent/pkg/util/log => ../../../../../../pkg/util/log
	github.com/DataDog/datadog-agent/pkg/util/log/setup => ../../../../../../pkg/util/log/setup
	github.com/DataDog/datadog-agent/pkg/util/option => ../../../../../../pkg/util/option
	github.com/DataDog/datadog-agent/pkg/util/otel => ../../../../../../pkg/util/otel
	github.com/DataDog/datadog-agent/pkg/util/pointer => ../../../../../../pkg/util/pointer
	github.com/DataDog/datadog-agent/pkg/util/prometheus => ../../../../../../pkg/util/prometheus
	github.com/DataDog/datadog-agent/pkg/util/quantile => ../../../../../../pkg/util/quantile
	github.com/DataDog/datadog-agent/pkg/util/quantile/sketchtest => ../../../../../../pkg/util/quantile/sketchtest
	github.com/DataDog/datadog-agent/pkg/util/scrubber => ../../../../../../pkg/util/scrubber
	github.com/DataDog/datadog-agent/pkg/util/sort => ../../../../../../pkg/util/sort
	github.com/DataDog/datadog-agent/pkg/util/startstop => ../../../../../../pkg/util/startstop
	github.com/DataDog/datadog-agent/pkg/util/statstracker => ../../../../../../pkg/util/statstracker
	github.com/DataDog/datadog-agent/pkg/util/system => ../../../../../../pkg/util/system
	github.com/DataDog/datadog-agent/pkg/util/system/socket => ../../../../../../pkg/util/system/socket
	github.com/DataDog/datadog-agent/pkg/util/testutil => ../../../../../../pkg/util/testutil
	github.com/DataDog/datadog-agent/pkg/util/utilizationtracker => ../../../../../../pkg/util/utilizationtracker
	github.com/DataDog/datadog-agent/pkg/util/uuid => ../../../../../../pkg/util/uuid
	github.com/DataDog/datadog-agent/pkg/util/winutil => ../../../../../../pkg/util/winutil
	github.com/DataDog/datadog-agent/pkg/version => ../../../../../../pkg/version
	github.com/DataDog/datadog-agent/test/fakeintake => ../../../../../../test/fakeintake
	github.com/DataDog/datadog-agent/test/new-e2e => ../../../../../../test/new-e2e
	github.com/DataDog/datadog-agent/test/otel => ../../../../../../test/otel
)
