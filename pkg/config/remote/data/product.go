// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package data

// Product is a remote configuration product
type Product string

const (
	// ProductAPMSampling is the apm sampling product
	ProductAPMSampling Product = "APM_SAMPLING"
	// ProductCWSDD is the cloud workload security product
	ProductCWSDD Product = "CWS_DD"
	// ProductCWSCustom is the cloud workload security product
	ProductCWSCustom Product = "CWS_CUSTOM"
	// ProductCWSProfile is the cloud workload security product
	ProductCWSProfile Product = "CWS_SECURITY_PROFILES"
	// ProductAPMTracing is the apm tracing product
	ProductAPMTracing Product = "APM_TRACING"
	// ProductLiveDebugging is the dynamic instrumentation product
	ProductLiveDebugging = "LIVE_DEBUGGING"
	// ProductTesting1 is a testing product
	ProductTesting1 Product = "TESTING1"
	// ProductAgentTask is to receive agent task instruction, like a flare
	ProductAgentTask Product = "AGENT_TASK"
	// ProductAgentConfig is to receive agent configurations, like the log level
	ProductAgentConfig = "AGENT_CONFIG"
	// ProductAgentIntegrations is to receive integrations to schedule
	ProductAgentIntegrations = "AGENT_INTEGRATIONS"
	// ProductContainerAutoscalingSettings receives definition of container autoscaling
	ProductContainerAutoscalingSettings = "CONTAINER_AUTOSCALING_SETTINGS"
	// ProductContainerAutoscalingValues receives values for container autoscaling
	ProductContainerAutoscalingValues = "CONTAINER_AUTOSCALING_VALUES"
	// ProductDataStreamsLiveMessages is to capture messages from Kafka
	ProductDataStreamsLiveMessages = "DSM_LIVE_MESSAGES"
)

// ProductListToString converts a product list to string list
func ProductListToString(products []Product) []string {
	stringProducts := make([]string, len(products))
	for i, product := range products {
		stringProducts[i] = string(product)
	}
	return stringProducts
}

// StringListToProduct converts a string list to product list
func StringListToProduct(stringProducts []string) []Product {
	products := make([]Product, len(stringProducts))
	for i, product := range stringProducts {
		products[i] = Product(product)
	}
	return products
}
