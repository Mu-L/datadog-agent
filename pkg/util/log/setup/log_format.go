// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !serverless

package logs

import (
	"fmt"
	"strings"

	"github.com/cihub/seelog"

	pkgconfigmodel "github.com/DataDog/datadog-agent/pkg/config/model"
)

// buildCommonFormat returns the log common format seelog string
func buildCommonFormat(loggerName LoggerName, cfg pkgconfigmodel.Reader) string {
	if loggerName == "JMXFETCH" {
		return `%Msg%n`
	}
	return fmt.Sprintf("%%Date(%s) | %s | %%LEVEL | (%%ShortFilePath:%%Line in %%FuncShort) | %%ExtraTextContext%%Msg%%n", getLogDateFormat(cfg), loggerName)
}

// buildJSONFormat returns the log JSON format seelog string
func buildJSONFormat(loggerName LoggerName, cfg pkgconfigmodel.Reader) string {
	_ = seelog.RegisterCustomFormatter("QuoteMsg", createQuoteMsgFormatter)
	if loggerName == "JMXFETCH" {
		return `{"msg":%QuoteMsg}%n`
	}
	return fmt.Sprintf(`{"agent":"%s","time":"%%Date(%s)","level":"%%LEVEL","file":"%%ShortFilePath","line":"%%Line","func":"%%FuncShort","msg":%%QuoteMsg%%ExtraJSONContext}%%n`, strings.ToLower(string(loggerName)), getLogDateFormat(cfg))
}
