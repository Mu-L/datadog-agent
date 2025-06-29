// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package processor

import (
	"regexp"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/comp/core/hostname/hostnameinterface"
	"github.com/DataDog/datadog-agent/comp/logs/agent/config"
	"github.com/DataDog/datadog-agent/pkg/logs/diagnostic"
	"github.com/DataDog/datadog-agent/pkg/logs/message"
	"github.com/DataDog/datadog-agent/pkg/logs/metrics"
	"github.com/DataDog/datadog-agent/pkg/logs/sds"
	"github.com/DataDog/datadog-agent/pkg/logs/sources"
)

type processorTestCase struct {
	source        sources.LogSource
	input         []byte
	output        []byte
	shouldProcess bool
	matchCount    int64
	ruleType      string
}

// exclusions tests
// ----------------
var exclusionRuleType = "exclude_at_match"
var exclusionTests = []processorTestCase{
	{
		source:        newSource(exclusionRuleType, "", "world"),
		input:         []byte("hello"),
		output:        []byte("hello"),
		shouldProcess: true,
		matchCount:    0,
		ruleType:      exclusionRuleType,
	},
	{
		source:        newSource(exclusionRuleType, "", "world"),
		input:         []byte("world"),
		output:        []byte{},
		shouldProcess: false,
		matchCount:    1,
		ruleType:      exclusionRuleType,
	},
	{
		source:        newSource(exclusionRuleType, "", "world"),
		input:         []byte("a brand new world"),
		output:        []byte{},
		shouldProcess: false,
		matchCount:    1,
		ruleType:      exclusionRuleType,
	},
	{
		source:        newSource(exclusionRuleType, "", "$world"),
		input:         []byte("a brand new world"),
		output:        []byte("a brand new world"),
		shouldProcess: true,
		matchCount:    0,
		ruleType:      exclusionRuleType,
	},
}

func TestExclusion(t *testing.T) {
	p := &Processor{}
	assert := assert.New(t)

	// unstructured messages

	for idx, test := range exclusionTests {
		msg := newMessage(test.input, &test.source, "")
		shouldProcess := p.applyRedactingRules(msg)
		assert.Equal(test.shouldProcess, shouldProcess)
		assert.Equal(test.matchCount, msg.Origin.LogSource.ProcessingInfo.GetCount(test.ruleType+":"+ruleName), "match count should be equal for test %d", idx)
		if test.shouldProcess {
			assert.Equal(test.output, msg.GetContent())
		}
		msg.Origin.LogSource.ProcessingInfo.Reset()
	}

	// structured messages

	for idx, test := range exclusionTests {
		msg := newStructuredMessage(test.input, &test.source, "")
		shouldProcess := p.applyRedactingRules(msg)
		assert.Equal(test.shouldProcess, shouldProcess)
		assert.Equal(test.matchCount, msg.Origin.LogSource.ProcessingInfo.GetCount(test.ruleType+":"+ruleName), "match count should be equal for test %d", idx)
		if test.shouldProcess {
			assert.Equal(test.output, msg.GetContent())
		}
		msg.Origin.LogSource.ProcessingInfo.Reset()
	}
}

// inclusion tests
// ---------------

var inclusionRuleType = "include_at_match"
var inclusionTests = []processorTestCase{
	{
		source:        *sources.NewLogSource("", &config.LogsConfig{}),
		input:         []byte("hello"),
		output:        []byte("hello"),
		shouldProcess: false,
		matchCount:    0,
		ruleType:      inclusionRuleType,
	},
	{
		source:        *sources.NewLogSource("", &config.LogsConfig{}),
		input:         []byte("world"),
		output:        []byte("world"),
		shouldProcess: true,
		matchCount:    1,
		ruleType:      inclusionRuleType,
	},
	{
		source:        *sources.NewLogSource("", &config.LogsConfig{}),
		input:         []byte("a brand new world"),
		output:        []byte("a brand new world"),
		shouldProcess: true,
		matchCount:    1,
	},
	{
		source:        newSource(inclusionRuleType, "", "^world"),
		input:         []byte("a brand new world"),
		output:        []byte("a brand new world"),
		shouldProcess: false,
		matchCount:    1,
	},
}

func TestInclusion(t *testing.T) {
	p := &Processor{processingRules: []*config.ProcessingRule{newProcessingRule(inclusionRuleType, "", "world")}}
	assert := assert.New(t)

	// unstructured messages

	for idx, test := range inclusionTests {
		msg := newMessage(test.input, &test.source, "")
		shouldProcess := p.applyRedactingRules(msg)
		assert.Equal(test.shouldProcess, shouldProcess)
		assert.Equal(test.matchCount, msg.Origin.LogSource.ProcessingInfo.GetCount(inclusionRuleType+":"+ruleName), "match count should be equal for test %d", idx)
		if test.shouldProcess {
			assert.Equal(test.output, msg.GetContent())
		}
		msg.Origin.LogSource.ProcessingInfo.Reset()
	}

	// structured messages

	for idx, test := range inclusionTests {
		msg := newStructuredMessage(test.input, &test.source, "")
		shouldProcess := p.applyRedactingRules(msg)
		assert.Equal(test.shouldProcess, shouldProcess)
		assert.Equal(test.matchCount, msg.Origin.LogSource.ProcessingInfo.GetCount(inclusionRuleType+":"+ruleName), "match count should be equal for test %d", idx)
		if test.shouldProcess {
			assert.Equal(test.output, msg.GetContent())
		}
		msg.Origin.LogSource.ProcessingInfo.Reset()
	}

}

// exclusion with inclusion tests
// ------------------------------

var exclusionRule *config.ProcessingRule = newProcessingRule(exclusionRuleType, "", "^bob")
var inclusionRule *config.ProcessingRule = newProcessingRule(inclusionRuleType, "", ".*@datadoghq.com$")

var exclusionInclusionTests = []processorTestCase{
	{
		source:        *sources.NewLogSource("", &config.LogsConfig{ProcessingRules: []*config.ProcessingRule{inclusionRule}}),
		input:         []byte("bob@datadoghq.com"),
		output:        []byte("bob@datadoghq.com"),
		shouldProcess: false,
		matchCount:    1,
		ruleType:      exclusionRuleType,
	},
	{
		source:        *sources.NewLogSource("", &config.LogsConfig{ProcessingRules: []*config.ProcessingRule{inclusionRule}}),
		input:         []byte("bill@datadoghq.com"),
		output:        []byte("bill@datadoghq.com"),
		shouldProcess: true,
		matchCount:    1,
		ruleType:      inclusionRuleType,
	},
	{
		source:        *sources.NewLogSource("", &config.LogsConfig{ProcessingRules: []*config.ProcessingRule{inclusionRule}}),
		input:         []byte("bob@amail.com"),
		output:        []byte("bob@amail.com"),
		shouldProcess: false,
		matchCount:    1,
		ruleType:      exclusionRuleType,
	},
	{
		source:        *sources.NewLogSource("", &config.LogsConfig{ProcessingRules: []*config.ProcessingRule{inclusionRule}}),
		input:         []byte("bill@amail.com"),
		output:        []byte("bill@amail.com"),
		shouldProcess: false,
		matchCount:    0,
		ruleType:      inclusionRuleType,
	},
}

func TestExclusionWithInclusion(t *testing.T) {
	p := &Processor{processingRules: []*config.ProcessingRule{exclusionRule}}
	assert := assert.New(t)

	// unstructured messages

	for idx, test := range exclusionInclusionTests {
		msg := newMessage(test.input, &test.source, "")
		shouldProcess := p.applyRedactingRules(msg)
		assert.Equal(test.shouldProcess, shouldProcess)
		assert.Equal(test.matchCount, msg.Origin.LogSource.ProcessingInfo.GetCount(test.ruleType+":"+ruleName), "match count should be equal for test %d", idx)
		if test.shouldProcess {
			assert.Equal(test.output, msg.GetContent())
		}
		msg.Origin.LogSource.ProcessingInfo.Reset()
	}

	// structured messages

	for idx, test := range exclusionInclusionTests {
		msg := newStructuredMessage(test.input, &test.source, "")
		shouldProcess := p.applyRedactingRules(msg)
		assert.Equal(test.shouldProcess, shouldProcess)
		assert.Equal(test.matchCount, msg.Origin.LogSource.ProcessingInfo.GetCount(test.ruleType+":"+ruleName), "match count should be equal for test %d", idx)
		if test.shouldProcess {
			assert.Equal(test.output, msg.GetContent())
		}
		msg.Origin.LogSource.ProcessingInfo.Reset()
	}
}

// mask_sequences test cases
// -------------------------
var maskSequenceRule = "mask_sequences"
var masksTests = []processorTestCase{
	{
		source:        newSource(maskSequenceRule, "[masked_world]", "world"),
		input:         []byte("hello"),
		output:        []byte("hello"),
		shouldProcess: true,
		matchCount:    0,
		ruleType:      maskSequenceRule,
	},
	{
		source:        newSource(maskSequenceRule, "[masked_world]", "world"),
		input:         []byte("hello world!"),
		output:        []byte("hello [masked_world]!"),
		shouldProcess: true,
		matchCount:    1,
		ruleType:      maskSequenceRule,
	},
	{
		source:        newSource(maskSequenceRule, "[masked_user]", "User=\\w+@datadoghq.com"),
		input:         []byte("new test launched by User=beats@datadoghq.com on localhost"),
		output:        []byte("new test launched by [masked_user] on localhost"),
		shouldProcess: true,
		matchCount:    1,
		ruleType:      maskSequenceRule,
	},
	{
		source:        newSource(maskSequenceRule, "[masked_credit_card]", "(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})"),
		input:         []byte("The credit card 4323124312341234 was used to buy some time"),
		output:        []byte("The credit card [masked_credit_card] was used to buy some time"),
		shouldProcess: true,
		matchCount:    1,
		ruleType:      maskSequenceRule,
	},
	{
		source:        newSource(maskSequenceRule, "${1}[masked_value]", "([Dd]ata_?values=)\\S+"),
		input:         []byte("New data added to Datavalues=123456 on prod"),
		output:        []byte("New data added to Datavalues=[masked_value] on prod"),
		shouldProcess: true,
		matchCount:    1,
		ruleType:      maskSequenceRule,
	},
	{
		source:        newSource(maskSequenceRule, "${1}[masked_value]", "([Dd]ata_?values=)\\S+"),
		input:         []byte("New data added to data_values=123456 on prod"),
		output:        []byte("New data added to data_values=[masked_value] on prod"),
		shouldProcess: true,
		matchCount:    1,
		ruleType:      maskSequenceRule,
	},
	{
		source:        newSource(maskSequenceRule, "${1}[masked_value]", "([Dd]ata_?values=)\\S+"),
		input:         []byte("New data added to data_values= on prod"),
		output:        []byte("New data added to data_values= on prod"),
		shouldProcess: true,
		matchCount:    0,
		ruleType:      maskSequenceRule,
	},
}

func TestMask(t *testing.T) {
	p := &Processor{}
	assert := assert.New(t)

	// unstructured messages

	for idx, maskTest := range masksTests {
		msg := newMessage(maskTest.input, &maskTest.source, "")
		shouldProcess := p.applyRedactingRules(msg)
		assert.Equal(maskTest.shouldProcess, shouldProcess)
		assert.Equal(maskTest.matchCount, msg.Origin.LogSource.ProcessingInfo.GetCount(maskSequenceRule+":"+ruleName), "match count should be equal for test %d", idx)
		if maskTest.shouldProcess {
			assert.Equal(maskTest.output, msg.GetContent())
		}
		msg.Origin.LogSource.ProcessingInfo.Reset()
	}

	// structured messages

	for idx, maskTest := range masksTests {
		msg := newStructuredMessage(maskTest.input, &maskTest.source, "")
		shouldProcess := p.applyRedactingRules(msg)
		assert.Equal(maskTest.shouldProcess, shouldProcess)
		assert.Equal(maskTest.matchCount, msg.Origin.LogSource.ProcessingInfo.GetCount(maskSequenceRule+":"+ruleName), "match count should be equal for test %d", idx)
		if maskTest.shouldProcess {
			assert.Equal(maskTest.output, msg.GetContent())
		}
		msg.Origin.LogSource.ProcessingInfo.Reset()
	}
}

func TestTruncate(t *testing.T) {
	p := &Processor{}
	source := sources.NewLogSource("", &config.LogsConfig{})
	msg := newMessage([]byte("hello"), source, "")
	_ = p.applyRedactingRules(msg)
	assert.Equal(t, []byte("hello"), msg.GetContent())
}

func TestGetHostnameLambda(t *testing.T) {
	p := &Processor{}
	m := message.NewMessage([]byte("hello"), nil, "", 0)
	m.ServerlessExtra = message.ServerlessExtra{
		Lambda: &message.Lambda{
			ARN: "testHostName",
		},
	}
	assert.Equal(t, "testHostName", p.GetHostname(m))
}

func TestGetHostname(t *testing.T) {
	hostnameComponent, _ := hostnameinterface.NewMock("testHostnameFromEnvVar")
	p := &Processor{
		hostname: hostnameComponent,
	}
	m := message.NewMessage([]byte("hello"), nil, "", 0)
	assert.Equal(t, "testHostnameFromEnvVar", p.GetHostname(m))
}

func TestBuffering(t *testing.T) {
	assert := assert.New(t)

	if !sds.SDSEnabled { // should not run when SDS is not builtin.
		return
	}

	hostnameComponent, _ := hostnameinterface.NewMock("testHostnameFromEnvVar")
	pm := metrics.NewNoopPipelineMonitor("")

	p := &Processor{
		encoder:                   JSONEncoder,
		inputChan:                 make(chan *message.Message),
		outputChan:                make(chan *message.Message),
		ReconfigChan:              make(chan sds.ReconfigureOrder),
		diagnosticMessageReceiver: diagnostic.NewBufferedMessageReceiver(nil, hostnameComponent),
		done:                      make(chan struct{}),
		// configured to buffer (max 3 messages)
		sds: sdsProcessor{
			maxBufferSize: len("hello1world") + len("hello2world") + len("hello3world") + 1,
			buffering:     true,
			scanner:       sds.CreateScanner("42"),
		},
		pipelineMonitor: pm,
		utilization:     pm.MakeUtilizationMonitor("processor"),
	}

	var processedMessages atomic.Int32

	// consumer
	go func() {
		for {
			<-p.outputChan
			processedMessages.Add(1)
		}
	}()

	// test the buffering when the processor is waiting for an SDS config
	// --

	p.Start()
	assert.Len(p.sds.buffer, 0)

	// validates it buffers these 3 messages
	src := newSource("exclude_at_match", "", "foobar")
	p.inputChan <- newMessage([]byte("hello1world"), &src, "")
	p.inputChan <- newMessage([]byte("hello2world"), &src, "")
	p.inputChan <- newMessage([]byte("hello3world"), &src, "")
	// wait for the other routine to process the messages
	messagesDequeue(t, func() bool { return processedMessages.Load() == 0 }, "the messages should not be be procesesd")

	// the limit is configured to 3 messages
	p.inputChan <- newMessage([]byte("hello4world"), &src, "")
	messagesDequeue(t, func() bool { return processedMessages.Load() == 0 }, "the messages should still not be processed")

	// reconfigure the processor
	// --

	// standard rules
	order := sds.ReconfigureOrder{
		Type: sds.StandardRules,
		Config: []byte(`{"priority":1,"is_enabled":true,"rules":[
                {
                    "id":"zero-0",
                    "description":"zero desc",
                    "name":"zero",
                    "definitions": [{"version":1, "pattern":"zero"}]
                }]}`),
		ResponseChan: make(chan sds.ReconfigureResponse),
	}

	p.ReconfigChan <- order
	resp := <-order.ResponseChan
	assert.Nil(resp.Err)
	assert.False(resp.IsActive)
	assert.True(p.sds.buffering)
	close(order.ResponseChan)

	// agent config, but no active rule
	order = sds.ReconfigureOrder{
		Type: sds.AgentConfig,
		Config: []byte(` {"is_enabled":true,"rules":[
            {
                "id": "random000",
                "name":"zero",
                "definition":{"standard_rule_id":"zero-0"},
                "match_action":{"type":"Redact","placeholder":"[redacted]"},
                "is_enabled":false
        }]}`),
		ResponseChan: make(chan sds.ReconfigureResponse),
	}

	p.ReconfigChan <- order
	resp = <-order.ResponseChan
	assert.Nil(resp.Err)
	assert.False(resp.IsActive)
	assert.True(p.sds.buffering)
	close(order.ResponseChan)

	// agent config, but the scanner becomes active:
	//   * the logs agent should stop buffering
	//   * it should drains its buffer and process the buffered logs

	// first, check that the buffer is still full
	messagesDequeue(t, func() bool { return processedMessages.Load() == 0 }, "no messages should be processed just yet")

	order = sds.ReconfigureOrder{
		Type: sds.AgentConfig,
		Config: []byte(` {"is_enabled":true,"rules":[
            {
                "id": "random000",
                "name":"zero",
                "definition":{"standard_rule_id":"zero-0"},
                "match_action":{"type":"Redact","placeholder":"[redacted]"},
                "is_enabled":true
        }]}`),
		ResponseChan: make(chan sds.ReconfigureResponse),
	}

	p.ReconfigChan <- order
	resp = <-order.ResponseChan

	assert.Nil(resp.Err)
	assert.True(resp.IsActive)
	assert.False(p.sds.buffering) // not buffering anymore
	close(order.ResponseChan)

	// make sure all messages have been drained and processed
	messagesDequeue(t, func() bool { return processedMessages.Load() == 3 }, "all messages must be drained")

	// make sure it continues to process normally without buffering now
	p.inputChan <- newMessage([]byte("usual work"), &src, "")
	messagesDequeue(t, func() bool { return processedMessages.Load() == 4 }, "should continue processing now")
}

// messagesDequeue let the other routines being scheduled
// to give some time for the processor routine to dequeue its messages
func messagesDequeue(t *testing.T, f func() bool, errorLog string) {
	timerTest := time.NewTimer(10 * time.Millisecond)
	timerTimeout := time.NewTimer(5 * time.Second)
	for {
		select {
		case <-timerTimeout.C:
			timerTest.Stop()
			timerTimeout.Stop()
			t.Error("timeout while message dequeuing in the processor")
			t.Fatal(errorLog)
			break
		case <-timerTest.C:
			if f() {
				timerTest.Stop()
				timerTimeout.Stop()
				return
			}
		}
	}
}

// helpers
// -

var ruleName = "test"

func newProcessingRule(ruleType, replacePlaceholder, pattern string) *config.ProcessingRule {
	return &config.ProcessingRule{
		Type:               ruleType,
		Name:               ruleName,
		ReplacePlaceholder: replacePlaceholder,
		Placeholder:        []byte(replacePlaceholder),
		Pattern:            pattern,
		Regex:              regexp.MustCompile(pattern),
	}
}

func newSource(ruleType, replacePlaceholder, pattern string) sources.LogSource {
	return *sources.NewLogSource("", &config.LogsConfig{ProcessingRules: []*config.ProcessingRule{newProcessingRule(ruleType, replacePlaceholder, pattern)}})
}

func newMessage(content []byte, source *sources.LogSource, status string) *message.Message {
	return message.NewMessageWithSource(content, status, source, 0)
}

func newStructuredMessage(content []byte, source *sources.LogSource, status string) *message.Message {
	structuredContent := message.BasicStructuredContent{
		Data: make(map[string]interface{}),
	}
	msg := message.NewStructuredMessage(&structuredContent, message.NewOrigin(source), status, 0)
	msg.SetContent(content)
	return msg
}

func BenchmarkMaskSequences(b *testing.B) {
	processor := &Processor{
		processingRules: []*config.ProcessingRule{
			{
				Type:               config.MaskSequences,
				Regex:              regexp.MustCompile("(?:api_key=[a-f0-9]{28})"),
				ReplacePlaceholder: "api_key=****************************",
			},
		},
	}

	msg := newMessage(nil, &sources.LogSource{
		Config: &config.LogsConfig{},
	}, "")

	b.Run("always matching", func(b *testing.B) {
		// what we benchmark here is the worse case scenario where the regex matches every time
		content := []byte("[1234] log message, api_key=1234567890123456789012345678")
		b.ResetTimer()

		for range b.N {
			msg.SetContent(content)
			processor.applyRedactingRules(msg)
		}
	})

	b.Run("never matching", func(b *testing.B) {
		// what we benchmark here is the best case scenario where the regex never matches
		content := []byte("nothing to see here")
		b.ResetTimer()

		for range b.N {
			msg.SetContent(content)
			processor.applyRedactingRules(msg)
		}
	})

}
