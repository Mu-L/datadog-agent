// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package log

import (
	logConfig "github.com/DataDog/datadog-agent/comp/logs/agent/config"
	"io"
	"testing"
)

func TestChannelWriter_Write(t *testing.T) {
	ch := make(chan *logConfig.ChannelMessage, 10)
	cw := NewChannelWriter(ch, false)

	// Test writing without a newline
	_, err := cw.Write([]byte("test"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(ch) != 0 {
		t.Fatalf("Expected channel to be empty, but it wasn't")
	}

	// Test writing with a single newline
	_, err = cw.Write([]byte("test\n"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(ch) != 1 {
		t.Fatalf("Expected channel to have 1 message, but it has %d", len(ch))
	}
	msg := <-ch
	if string(msg.Content) != "testtest" {
		t.Fatalf("Expected message content 'testtest' but got '%s'", msg.Content)
	}

	// Test writing multiple newlines
	_, err = cw.Write([]byte("line1\nline2\nline3\n"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(ch) != 3 {
		t.Fatalf("Expected channel to have 3 messages, but it has %d", len(ch))
	}
	expectedLines := []string{"line1", "line2", "line3"}
	for _, expected := range expectedLines {
		msg := <-ch
		if string(msg.Content) != expected {
			t.Fatalf("Expected message content '%s' but got '%s'", expected, msg.Content)
		}
	}

	// Test sending data without flushing with a newline
	_, err = cw.Write([]byte("partial"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(ch) != 0 {
		t.Fatalf("Expected channel to be empty after sending partial data, but it wasn't")
	}
	// Complete the message with a newline and check it's sent
	_, err = cw.Write([]byte(" data\n"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(ch) != 1 {
		t.Fatalf("Expected channel to have 1 message after completing the message, but it has %d", len(ch))
	}
	msg = <-ch
	if string(msg.Content) != "partial data" {
		t.Fatalf("Expected message content 'partial data', but got '%s'", msg.Content)
	}
}

func TestChannelWriter_WriteError(t *testing.T) {
	ch := make(chan *logConfig.ChannelMessage, 10)
	cw := NewChannelWriter(ch, true)

	cw.Write([]byte("Some error\n"))
	if len(ch) != 1 {
		t.Fatalf("Expected channel to have 1 message, but it has %d", len(ch))
	}
	msg := <-ch
	if string(msg.Content) != "Some error\n" {
		t.Fatalf("Expected message content 'Some error' but got '%s'", msg.Content)
	}

	// Test writing with a multiline stacktrace
	message := "Some error\n  at someFile at line 39\n  at someFile at line 51\nSome error occurred.\n"
	cw.Write([]byte(message))
	if len(ch) != 1 {
		t.Fatalf("Expected channel to have 1 message, but it has %d", len(ch))
	}
	msg = <-ch
	if string(msg.Content) != message {
		t.Fatalf("Expected message content '%s' but got '%s'", message, msg.Content)
	}
}

func TestChannelWriter_ReturnsLength(t *testing.T) {
	ch := make(chan *logConfig.ChannelMessage, 1)
	cw := NewChannelWriter(ch, true)

	mw := io.MultiWriter(io.Discard, cw)

	payload := []byte("test error\n")
	n, err := mw.Write(payload)

	if err != nil {
		t.Fatalf(
			"MultiWriter.Write returned an error; likely ChannelWriter.Write returned n < len(p). Error: %v", err,
		)
	}
	if n != len(payload) {
		t.Fatalf("MultiWriter.Write returned %d; expected %d", n, len(payload))
	}

	if len(ch) != 1 {
		t.Fatalf("Expected 1 message in channel, got %d", len(ch))
	}
	msg := <-ch
	if string(msg.Content) != string(payload) {
		t.Fatalf("Expected channel content %q, got %q", string(payload), msg.Content)
	}
}
