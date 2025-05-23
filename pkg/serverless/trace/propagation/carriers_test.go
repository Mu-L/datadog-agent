// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package propagation

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/serverless/trigger/events"
	"github.com/DataDog/datadog-agent/pkg/trace/sampler"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

func getMapFromCarrier(tm tracer.TextMapReader) map[string]string {
	if tm == nil {
		return nil
	}
	m := map[string]string{}
	tm.ForeachKey(func(key, val string) error {
		m[key] = val
		return nil
	})
	return m
}

func TestSQSMessageAttrCarrier(t *testing.T) {
	testcases := []struct {
		name     string
		attr     events.SQSMessageAttribute
		expMap   map[string]string
		expNoErr bool
	}{
		{
			name: "string-datadog-map",
			attr: events.SQSMessageAttribute{
				DataType:    "String",
				StringValue: aws.String(headersAll),
			},
			expMap:   headersMapAll,
			expNoErr: true,
		},
		{
			name: "string-empty-map",
			attr: events.SQSMessageAttribute{
				DataType:    "String",
				StringValue: aws.String("{}"),
			},
			expMap:   map[string]string{},
			expNoErr: true,
		},
		{
			name: "string-empty-string",
			attr: events.SQSMessageAttribute{
				DataType:    "String",
				StringValue: aws.String(""),
			},
			expMap:   nil,
			expNoErr: false,
		},
		{
			name: "string-nil-string",
			attr: events.SQSMessageAttribute{
				DataType:    "String",
				StringValue: nil,
			},
			expMap:   nil,
			expNoErr: false,
		},
		{
			name: "binary-datadog-map",
			attr: events.SQSMessageAttribute{
				DataType:    "Binary",
				BinaryValue: []byte(headersAll),
			},
			expMap:   headersMapAll,
			expNoErr: true,
		},
		{
			name: "binary-empty-map",
			attr: events.SQSMessageAttribute{
				DataType:    "Binary",
				BinaryValue: []byte("{}"),
			},
			expMap:   map[string]string{},
			expNoErr: true,
		},
		{
			name: "binary-empty-string",
			attr: events.SQSMessageAttribute{
				DataType:    "Binary",
				BinaryValue: []byte(""),
			},
			expMap:   nil,
			expNoErr: false,
		},
		{
			name: "binary-nil-string",
			attr: events.SQSMessageAttribute{
				DataType:    "Binary",
				BinaryValue: nil,
			},
			expMap:   nil,
			expNoErr: false,
		},
		{
			name: "wrong-data-type",
			attr: events.SQSMessageAttribute{
				DataType: "Purple",
			},
			expMap:   nil,
			expNoErr: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tm, err := sqsMessageAttrCarrier(tc.attr)
			t.Logf("sqsMessageAttrCarrier returned TextMapReader=%#v error=%#v", tm, err)
			assert.Equal(t, tc.expNoErr, err == nil)
			assert.Equal(t, tc.expMap, getMapFromCarrier(tm))
		})
	}
}

func TestSnsSqsMessageCarrier(t *testing.T) {
	testcases := []struct {
		name   string
		event  events.SQSMessage
		expMap map[string]string
		expErr string
	}{
		{
			name: "empty-string-body",
			event: events.SQSMessage{
				Body: "",
			},
			expMap: nil,
			expErr: "Error unmarshaling message body:",
		},
		{
			name: "empty-map-body",
			event: events.SQSMessage{
				Body: "{}",
			},
			expMap: nil,
			expErr: "No Datadog trace context found",
		},
		{
			name: "no-msg-attrs",
			event: events.SQSMessage{
				Body: `{
					"MessageAttributes": {}
				}`,
			},
			expMap: nil,
			expErr: "No Datadog trace context found",
		},
		{
			name: "wrong-type-msg-attrs",
			event: events.SQSMessage{
				Body: `{
					"MessageAttributes": "attrs"
				}`,
			},
			expMap: nil,
			expErr: "Error unmarshaling message body:",
		},
		{
			name: "non-binary-type",
			event: events.SQSMessage{
				Body: `{
					"MessageAttributes": {
						"_datadog": {
							"Type": "Purple",
							"Value": "Value"
						}
					}
				}`,
			},
			expMap: nil,
			expErr: "Unsupported Type in _datadog payload",
		},
		{
			name: "cannot-decode",
			event: events.SQSMessage{
				Body: `{
					"MessageAttributes": {
						"_datadog": {
							"Type": "Binary",
							"Value": "Value"
						}
					}
				}`,
			},
			expMap: nil,
			expErr: "Error decoding binary:",
		},
		{
			name: "empty-string-encoded",
			event: events.SQSMessage{
				Body: `{
					"MessageAttributes": {
						"_datadog": {
							"Type": "Binary",
							"Value": "` + base64.StdEncoding.EncodeToString([]byte(``)) + `"
						}
					}
				}`,
			},
			expMap: nil,
			expErr: "Error unmarshaling the decoded binary:",
		},
		{
			name:   "empty-map-encoded",
			event:  eventSqsMessage(headersNone, headersEmpty, headersNone),
			expMap: headersMapEmpty,
			expErr: "",
		},
		{
			name:   "datadog-map",
			event:  eventSqsMessage(headersNone, headersAll, headersNone),
			expMap: headersMapAll,
			expErr: "",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tm, err := snsSqsMessageCarrier(tc.event)
			t.Logf("snsSqsMessageCarrier returned TextMapReader=%#v error=%#v", tm, err)
			assert.Equal(t, tc.expErr != "", err != nil)
			if tc.expErr != "" {
				assert.ErrorContains(t, err, tc.expErr)
			}
			assert.Equal(t, tc.expMap, getMapFromCarrier(tm))
		})
	}
}

func TestSnsEntityCarrier(t *testing.T) {
	testcases := []struct {
		name   string
		event  events.SNSEntity
		expMap map[string]string
		expErr string
	}{
		{
			name: "eventbridge-through-sns",
			event: events.SNSEntity{
				Message: `{"detail":{"_datadog":{"x-datadog-trace-id":"123456789","x-datadog-parent-id":"987654321","x-datadog-sampling-priority":"1"}}}`,
			},
			expMap: map[string]string{
				"x-datadog-trace-id":          "123456789",
				"x-datadog-parent-id":         "987654321",
				"x-datadog-sampling-priority": "1",
			},
			expErr: "",
		},
		{
			name:   "no-msg-attrs",
			event:  events.SNSEntity{},
			expMap: nil,
			expErr: "No Datadog trace context found",
		},
		{
			name: "wrong-type-msg-attrs",
			event: events.SNSEntity{
				MessageAttributes: map[string]interface{}{
					"_datadog": 12345,
				},
			},
			expMap: nil,
			expErr: "Unsupported type for _datadog payload",
		},
		{
			name: "wrong-type-type",
			event: events.SNSEntity{
				MessageAttributes: map[string]interface{}{
					"_datadog": map[string]interface{}{
						"Type":  12345,
						"Value": "Value",
					},
				},
			},
			expMap: nil,
			expErr: "Unsupported type in _datadog payload",
		},
		{
			name: "wrong-value-type",
			event: events.SNSEntity{
				MessageAttributes: map[string]interface{}{
					"_datadog": map[string]interface{}{
						"Type":  "Binary",
						"Value": 12345,
					},
				},
			},
			expMap: nil,
			expErr: "Unsupported value type in _datadog payload",
		},
		{
			name: "cannot-decode",
			event: events.SNSEntity{
				MessageAttributes: map[string]interface{}{
					"_datadog": map[string]interface{}{
						"Type":  "Binary",
						"Value": "Value",
					},
				},
			},
			expMap: nil,
			expErr: "Error decoding binary: illegal base64 data at input byte 4",
		},
		{
			name: "unknown-type",
			event: events.SNSEntity{
				MessageAttributes: map[string]interface{}{
					"_datadog": map[string]interface{}{
						"Type":  "Purple",
						"Value": "Value",
					},
				},
			},
			expMap: nil,
			expErr: "Unsupported Type in _datadog payload",
		},
		{
			name: "empty-string-encoded",
			event: events.SNSEntity{
				MessageAttributes: map[string]interface{}{
					"_datadog": map[string]interface{}{
						"Type":  "Binary",
						"Value": base64.StdEncoding.EncodeToString([]byte(``)),
					},
				},
			},
			expMap: nil,
			expErr: "Error unmarshaling the decoded binary:",
		},
		{
			name: "binary-type",
			event: events.SNSEntity{
				MessageAttributes: map[string]interface{}{
					"_datadog": map[string]interface{}{
						"Type":  "Binary",
						"Value": base64.StdEncoding.EncodeToString([]byte(headersAll)),
					},
				},
			},
			expMap: headersMapAll,
			expErr: "",
		},
		{
			name: "string-type",
			event: events.SNSEntity{
				MessageAttributes: map[string]interface{}{
					"_datadog": map[string]interface{}{
						"Type":  "String",
						"Value": headersAll,
					},
				},
			},
			expMap: headersMapAll,
			expErr: "",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tm, err := snsEntityCarrier(tc.event)
			t.Logf("snsEntityCarrier returned TextMapReader=%#v error=%#v", tm, err)
			assert.Equal(t, tc.expErr != "", err != nil)
			if tc.expErr != "" {
				assert.ErrorContains(t, err, tc.expErr)
			}
			assert.Equal(t, tc.expMap, getMapFromCarrier(tm))
		})
	}
}

func TestEventBridgeCarrier(t *testing.T) {
	testcases := []struct {
		name   string
		event  events.EventBridgeEvent
		expMap map[string]string
		expErr string
	}{
		{
			name: "valid_trace_context",
			event: events.EventBridgeEvent{
				Detail: struct {
					TraceContext map[string]string `json:"_datadog"`
				}{
					TraceContext: map[string]string{
						"x-datadog-trace-id":          "123456789",
						"x-datadog-parent-id":         "987654321",
						"x-datadog-sampling-priority": "1",
					},
				},
			},
			expMap: map[string]string{
				"x-datadog-trace-id":          "123456789",
				"x-datadog-parent-id":         "987654321",
				"x-datadog-sampling-priority": "1",
			},
			expErr: "",
		},
		{
			name: "missing_trace_context",
			event: events.EventBridgeEvent{
				Detail: struct {
					TraceContext map[string]string `json:"_datadog"`
				}{
					TraceContext: map[string]string{},
				},
			},
			expMap: nil,
			expErr: "No Datadog trace context found",
		},
		{
			name: "nil_trace_context",
			event: events.EventBridgeEvent{
				Detail: struct {
					TraceContext map[string]string `json:"_datadog"`
				}{
					TraceContext: nil,
				},
			},
			expMap: nil,
			expErr: "No Datadog trace context found",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tm, err := eventBridgeCarrier(tc.event)
			t.Logf("eventBridgeCarrier returned TextMapReader=%#v error=%#v", tm, err)
			assert.Equal(t, tc.expErr != "", err != nil)
			if tc.expErr != "" {
				assert.ErrorContains(t, err, tc.expErr)
			}
			assert.Equal(t, tc.expMap, getMapFromCarrier(tm))
		})
	}
}

func TestExtractTraceContextfromAWSTraceHeader(t *testing.T) {
	ctx := func(trace, parent, priority uint64) *TraceContext {
		return &TraceContext{
			TraceID:          trace,
			ParentID:         parent,
			SamplingPriority: sampler.SamplingPriority(priority),
		}
	}

	testcases := []struct {
		name     string
		value    string
		expTc    *TraceContext
		expNoErr bool
	}{
		{
			name:     "empty string",
			value:    "",
			expTc:    nil,
			expNoErr: false,
		},
		{
			name:     "root but no parent",
			value:    "Root=1-00000000-000000000000000000000001",
			expTc:    nil,
			expNoErr: false,
		},
		{
			name:     "parent but no root",
			value:    "Parent=0000000000000001",
			expTc:    nil,
			expNoErr: false,
		},
		{
			name:     "just root and parent",
			value:    "Root=1-00000000-000000000000000000000001;Parent=0000000000000001",
			expTc:    ctx(1, 1, 0),
			expNoErr: true,
		},
		{
			name:     "trailing semi-colon",
			value:    "Root=1-00000000-000000000000000000000001;Parent=0000000000000001;",
			expTc:    ctx(1, 1, 0),
			expNoErr: true,
		},
		{
			name:     "trailing semi-colons",
			value:    "Root=1-00000000-000000000000000000000001;Parent=0000000000000001;;;",
			expTc:    ctx(1, 1, 0),
			expNoErr: true,
		},
		{
			name:     "parent first",
			value:    "Parent=0000000000000009;Root=1-00000000-000000000000000000000001",
			expTc:    ctx(1, 9, 0),
			expNoErr: true,
		},
		{
			name:     "two roots",
			value:    "Root=1-00000000-000000000000000000000005;Parent=0000000000000009;Root=1-00000000-000000000000000000000001",
			expTc:    ctx(5, 9, 0),
			expNoErr: true,
		},
		{
			name:     "two parents",
			value:    "Root=1-00000000-000000000000000000000001;Parent=0000000000000009;Parent=0000000000000000",
			expTc:    ctx(1, 9, 0),
			expNoErr: true,
		},
		{
			name:     "sampled 0",
			value:    "Root=1-00000000-000000000000000000000001;Parent=0000000000000002;Sampled=0",
			expTc:    ctx(1, 2, 0),
			expNoErr: true,
		},
		{
			name:     "sampled 1",
			value:    "Root=1-00000000-000000000000000000000001;Parent=0000000000000002;Sampled=1",
			expTc:    ctx(1, 2, 1),
			expNoErr: true,
		},
		{
			name:     "sampled too big",
			value:    "Root=1-00000000-000000000000000000000001;Parent=0000000000000002;Sampled=5",
			expTc:    ctx(1, 2, 0),
			expNoErr: true,
		},
		{
			name:     "sampled first",
			value:    "Sampled=1;Root=1-00000000-000000000000000000000001;Parent=0000000000000002",
			expTc:    ctx(1, 2, 1),
			expNoErr: true,
		},
		{
			name:     "multiple sampled uses first 1",
			value:    "Root=1-00000000-000000000000000000000001;Parent=0000000000000002;Sampled=1;Sampled=0",
			expTc:    ctx(1, 2, 1),
			expNoErr: true,
		},
		{
			name:     "multiple sampled uses first 0",
			value:    "Root=1-00000000-000000000000000000000001;Parent=0000000000000002;Sampled=0;Sampled=1",
			expTc:    ctx(1, 2, 0),
			expNoErr: true,
		},
		{
			name:     "sampled empty",
			value:    "Root=1-00000000-000000000000000000000001;Parent=0000000000000002;Sampled=",
			expTc:    ctx(1, 2, 0),
			expNoErr: true,
		},
		{
			name:     "sampled empty then sampled found",
			value:    "Root=1-00000000-000000000000000000000001;Parent=0000000000000002;Sampled=;Sampled=1",
			expTc:    ctx(1, 2, 1),
			expNoErr: true,
		},
		{
			name:     "with lineage",
			value:    "Root=1-00000000-000000000000000000000001;Parent=0000000000000001;Lineage=a87bd80c:1|68fd508a:5|c512fbe3:2",
			expTc:    ctx(1, 1, 0),
			expNoErr: true,
		},
		{
			name:     "root too long",
			value:    "Root=1-00000000-0000000000000000000000010000;Parent=0000000000000001",
			expTc:    ctx(65536, 1, 0),
			expNoErr: true,
		},
		{
			name:     "parent too long",
			value:    "Root=1-00000000-000000000000000000000001;Parent=00000000000000010000",
			expTc:    ctx(1, 65536, 0),
			expNoErr: true,
		},
		{
			name:     "invalid root chars",
			value:    "Root=1-00000000-00000000000000000traceID;Parent=0000000000000000",
			expTc:    nil,
			expNoErr: false,
		},
		{
			name:     "invalid parent chars",
			value:    "Root=1-00000000-000000000000000000000000;Parent=0000000000spanID",
			expTc:    nil,
			expNoErr: false,
		},
		{
			name:     "invalid root and parent chars",
			value:    "Root=1-00000000-00000000000000000traceID;Parent=0000000000spanID",
			expTc:    nil,
			expNoErr: false,
		},
		{
			name:     "large trace-id",
			value:    "Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8",
			expTc:    nil,
			expNoErr: false,
		},
		{
			name:     "non-zero epoch",
			value:    "Root=1-5759e988-00000000e1be46a994272793;Parent=53995c3f42cd8ad8",
			expTc:    ctx(16266516598257821587, 6023947403358210776, 0),
			expNoErr: true,
		},
		{
			name:     "unknown key/value",
			value:    "Root=1-00000000-000000000000000000000001;Parent=0000000000000001;key=value",
			expTc:    ctx(1, 1, 0),
			expNoErr: true,
		},
		{
			name:     "key no value",
			value:    "Root=1-00000000-000000000000000000000001;Parent=0000000000000001;key=",
			expTc:    ctx(1, 1, 0),
			expNoErr: true,
		},
		{
			name:     "value no key",
			value:    "Root=1-00000000-000000000000000000000001;Parent=0000000000000001;=value",
			expTc:    ctx(1, 1, 0),
			expNoErr: true,
		},
		{
			name:     "extra chars suffix",
			value:    "Root=1-00000000-000000000000000000000001;Parent=0000000000000001;value",
			expTc:    ctx(1, 1, 0),
			expNoErr: true,
		},
		{
			name:     "root key no root value",
			value:    "Root=;Parent=0000000000000001",
			expTc:    nil,
			expNoErr: false,
		},
		{
			name:     "parent key no parent value",
			value:    "Root=1-00000000-000000000000000000000001;Parent=",
			expTc:    nil,
			expNoErr: false,
		},
		{
			name:     "bad trace id",
			value:    "Root=1-00000000-000000000000000000000001purple;Parent=0000000000000002;Sampled=1",
			expTc:    nil,
			expNoErr: false,
		},
		{
			name:     "bad parent id",
			value:    "Root=1-00000000-000000000000000000000001;Parent=0000000000000002purple;Sampled=1",
			expTc:    nil,
			expNoErr: false,
		},
		{
			name:     "zero value trace and parent id",
			value:    "Root=1-00000000-000000000000000000000000;Parent=0000000000000000;Sampled=1",
			expTc:    nil,
			expNoErr: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			ctx, err := extractTraceContextfromAWSTraceHeader(tc.value)
			t.Logf("extractTraceContextfromAWSTraceHeader returned TraceContext=%#v error=%#v", ctx, err)
			assert.Equal(tc.expTc, ctx)
			assert.Equal(tc.expNoErr, err == nil)
		})
	}
}

func TestSqsMessageCarrier(t *testing.T) {
	testcases := []struct {
		name   string
		event  events.SQSMessage
		expMap map[string]string
		expErr error
	}{
		{
			name:   "datadog-map",
			event:  eventSqsMessage(headersNone, headersAll, headersNone),
			expMap: headersMapAll,
			expErr: nil,
		},
		{
			name:   "datadog-map",
			event:  eventSqsMessage(headersAll, headersNone, headersNone),
			expMap: headersMapAll,
			expErr: nil,
		},
		{
			name: "eventbridge-through-sqs",
			event: events.SQSMessage{
				Body: `{"detail":{"_datadog":{"x-datadog-trace-id":"123456789","x-datadog-parent-id":"987654321","x-datadog-sampling-priority":"1"}}}`,
			},
			expMap: map[string]string{
				"x-datadog-trace-id":          "123456789",
				"x-datadog-parent-id":         "987654321",
				"x-datadog-sampling-priority": "1",
			},
			expErr: nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tm, err := sqsMessageCarrier(tc.event)
			t.Logf("sqsMessageCarrier returned TextMapReader=%#v error=%#v", tm, err)
			assert.Equal(t, tc.expErr == nil, err == nil)
			if err != nil {
				assert.Equal(t, tc.expErr.Error(), err.Error())
			}
			assert.Equal(t, tc.expMap, getMapFromCarrier(tm))
		})
	}
}

func TestRawPayloadCarrier(t *testing.T) {
	testcases := []struct {
		name   string
		event  []byte
		expMap map[string]string
		expErr error
	}{
		{
			name:   "empty-string",
			event:  []byte(headersNone),
			expMap: headersMapNone,
			expErr: errors.New("Could not unmarshal the invocation event payload"),
		},
		{
			name:   "empty-map",
			event:  []byte(headersEmpty),
			expMap: headersMapEmpty,
			expErr: nil,
		},
		{
			name:   "no-headers-key",
			event:  []byte(`{"hello":"world"}`),
			expMap: headersMapEmpty,
			expErr: nil,
		},
		{
			name:   "not-map-type",
			event:  []byte("[]"),
			expMap: headersMapNone,
			expErr: errors.New("Could not unmarshal the invocation event payload"),
		},
		{
			name:   "toplevel-headers-all",
			event:  []byte(headersAll),
			expMap: headersMapEmpty,
			expErr: nil,
		},
		{
			name:   "keyed-headers-all",
			event:  []byte(`{"headers":` + headersAll + `}`),
			expMap: headersMapAll,
			expErr: nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tm, err := rawPayloadCarrier(tc.event)
			t.Logf("rawPayloadCarrier returned TextMapReader=%#v error=%#v", tm, err)
			assert.Equal(t, tc.expErr != nil, err != nil)
			if tc.expErr != nil && err != nil {
				assert.Equal(t, tc.expErr.Error(), err.Error())
			}
			assert.Equal(t, tc.expMap, getMapFromCarrier(tm))
		})
	}
}

func TestHeadersCarrier(t *testing.T) {
	testcases := []struct {
		name   string
		event  map[string]string
		expMap map[string]string
		expErr error
	}{
		{
			name:   "nil-map",
			event:  headersMapNone,
			expMap: headersMapEmpty,
			expErr: nil,
		},
		{
			name:   "empty-map",
			event:  headersMapEmpty,
			expMap: headersMapEmpty,
			expErr: nil,
		},
		{
			name:   "headers-all",
			event:  headersMapAll,
			expMap: headersMapAll,
			expErr: nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tm, err := headersCarrier(tc.event)
			t.Logf("headersCarrier returned TextMapReader=%#v error=%#v", tm, err)
			assert.Equal(t, tc.expErr != nil, err != nil)
			if tc.expErr != nil && err != nil {
				assert.Equal(t, tc.expErr.Error(), err.Error())
			}
			assert.Equal(t, tc.expMap, getMapFromCarrier(tm))
		})
	}
}

func TestHeadersOrMultiheadersCarrier(t *testing.T) {
	testcases := []struct {
		name      string
		hdrs      map[string]string
		multiHdrs map[string][]string
		expMap    map[string]string
	}{
		{
			name:      "nil-map",
			hdrs:      headersMapNone,
			multiHdrs: toMultiValueHeaders(headersMapNone),
			expMap:    headersMapEmpty,
		},
		{
			name:      "empty-map",
			hdrs:      headersMapEmpty,
			multiHdrs: toMultiValueHeaders(headersMapEmpty),
			expMap:    headersMapEmpty,
		},
		{
			name:      "headers-and-multiheaders",
			hdrs:      headersMapDD,
			multiHdrs: toMultiValueHeaders(headersMapW3C),
			expMap:    headersMapDD,
		},
		{
			name:      "just-headers",
			hdrs:      headersMapDD,
			multiHdrs: toMultiValueHeaders(headersMapEmpty),
			expMap:    headersMapDD,
		},
		{
			name:      "just-multiheaders",
			hdrs:      headersMapEmpty,
			multiHdrs: toMultiValueHeaders(headersMapW3C),
			expMap:    headersMapW3C,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tm, err := headersOrMultiheadersCarrier(tc.hdrs, tc.multiHdrs)
			t.Logf("headersOrMultiheadersCarrier returned TextMapReader=%#v error=%#v", tm, err)
			assert.Nil(t, err)
			assert.Equal(t, tc.expMap, getMapFromCarrier(tm))
		})
	}
}

func Test_stringToDdSpanId(t *testing.T) {
	type args struct {
		execArn          string
		execRedriveCount uint16
		stateName        string
		stateEnteredTime string
		stateRetryCount  uint16
	}
	testcases := []struct {
		name string
		args args
		want uint64
	}{
		{"first Test Case",
			args{
				"arn:aws:states:sa-east-1:601427271234:express:DatadogStateMachine:acaf1a67-336a-e854-1599-2a627eb2dd8a:c8baf081-31f1-464d-971f-70cb17d01111",
				0,
				"step-one",
				"2022-12-08T21:08:19.224Z",
				0,
			},
			4340734536022949921,
		},
		{
			"second Test Case",
			args{
				"arn:aws:states:sa-east-1:601427271234:express:DatadogStateMachine:acaf1a67-336a-e854-1599-2a627eb2dd8a:c8baf081-31f1-464d-971f-70cb17d01111",
				0,
				"step-one",
				"2022-12-08T21:08:19.224Y",
				0,
			},
			981693280319792699,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equalf(t, tc.want, stringToDdSpanID(tc.args.execArn, tc.args.stateName, tc.args.stateEnteredTime, tc.args.stateRetryCount, tc.args.execRedriveCount), "stringToDdSpanID(%v, %v, %v)", tc.args.execArn, tc.args.stateName, tc.args.stateEnteredTime)
		})
	}
}

func Test_stringToDdTraceIds(t *testing.T) {
	type args struct {
		toHash string
	}
	testcases := []struct {
		name               string
		args               args
		expectedLower64    uint64
		expectedUpper64Hex string
	}{
		{
			"first Test Case",
			args{
				"arn:aws:states:sa-east-1:425362996713:stateMachine:MyStateMachine-b276uka1j",
			},
			1680583253837593461,
			"60ee1db79e4803f8",
		},
		{
			"lifecycle_test.go TestStartExecutionSpanStepFunctionEvent test case",
			args{
				"arn:aws:states:us-east-1:425362996713:execution:agocsTestSF:bc9f281c-3daa-4e5a-9a60-471a3810bf44",
			},
			5744042798732701615,
			"1914fe7789eb32be",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got, got1 := stringToDdTraceIDs(tc.args.toHash)
			assert.Equalf(t, tc.expectedLower64, got, "stringToDdTraceIDs(%v)", tc.args.toHash)
			assert.Equalf(t, tc.expectedUpper64Hex, got1, "stringToDdTraceIDs(%v)", tc.args.toHash)
		})
	}
}

func TestParseUpper64Bits(t *testing.T) {
	testcases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid_tid_at_start",
			input:    "_dd.p.tid=66bcb5eb00000000,_dd.p.dm=-0",
			expected: "66bcb5eb00000000",
		},
		{
			name:     "valid_tid_at_end",
			input:    "_dd.p.dm=-0,_dd.p.tid=abcdef1234567890",
			expected: "abcdef1234567890",
		},
		{
			name:     "no_tid_present",
			input:    "_dd.p.dm=-0",
			expected: "",
		},
		{
			name:     "empty_input",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			result := parseUpper64Bits(tc.input)
			assert.Equal(t, tc.expected, result, "For input '%s', expected '%s' but got '%s'", tc.input, tc.expected, result)
		})
	}
}
