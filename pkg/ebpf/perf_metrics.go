// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package ebpf

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	perfCollector *perfUsageCollector
)

// ReportPerfMetrics records metrics about a perf buffer or ring buffer usage and size
func ReportPerfMetrics(mapName string, mapType string, cpu int, count int, size int) {
	if perfCollector != nil {
		perfCollector.Set(mapName, mapType, cpu, count, size)
	}
}

// ReportPerfLost records metrics about lost samples in a perf buffer
func ReportPerfLost(mapName string, mapType string, cpu int, lostCount uint64) {
	if perfCollector != nil {
		perfCollector.SetLost(mapName, mapType, cpu, lostCount)
	}
}

type perfUsageCollector struct {
	usage    *maxGauge
	usagePct *maxGauge
	size     *maxGauge
	lost     *prometheus.CounterVec
}

// NewPerfUsageCollector creates a prometheus.Collector for perf buffer and ring buffer metrics
func NewPerfUsageCollector() prometheus.Collector {
	perfCollector = &perfUsageCollector{
		usage: newMaxGauge(prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Subsystem: "ebpf__perf",
				Name:      "_usage",
				Help:      "gauge tracking bytes usage of a perf buffer (per-cpu) or ring buffer",
			},
			[]string{"map_name", "map_type", "cpu_num"},
		)),
		usagePct: newMaxGauge(prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Subsystem: "ebpf__perf",
				Name:      "_usage_pct",
				Help:      "gauge tracking percentage usage of a perf buffer (per-cpu) or ring buffer",
			},
			[]string{"map_name", "map_type", "cpu_num"},
		)),
		size: newMaxGauge(prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Subsystem: "ebpf__perf",
				Name:      "_size",
				Help:      "gauge tracking total size of a perf buffer (per-cpu) or ring buffer",
			},
			[]string{"map_name", "map_type", "cpu_num"},
		)),
		lost: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Subsystem: "ebpf__perf",
				Name:      "_lost",
				Help:      "counter tracking lost samples of a perf buffer (per-cpu)",
			},
			[]string{"map_name", "map_type", "cpu_num"},
		),
	}
	return perfCollector
}

// Set updates metrics for perf buffer or ring buffer usage
func (p *perfUsageCollector) Set(mapName string, mapType string, cpu int, count int, size int) {
	p.usage.set(mapName, mapType, cpu, float64(count))
	p.size.set(mapName, mapType, cpu, float64(size))
	p.usagePct.set(mapName, mapType, cpu, 100*(float64(count)/float64(size)))
}

// SetLost updates metrics when a lost sample event occurs
func (p *perfUsageCollector) SetLost(mapName string, mapType string, cpu int, lostCount uint64) {
	size := p.size.get(mapName, cpu)
	if size > 0 {
		p.usage.set(mapName, mapType, cpu, size)
		p.usagePct.set(mapName, mapType, cpu, 100)
	}
	p.lost.WithLabelValues(mapName, mapType, strconv.Itoa(cpu)).Add(float64(lostCount))
}

// Describe implements prometheus.Collector.Describe
func (p *perfUsageCollector) Describe(descs chan<- *prometheus.Desc) {
	p.usage.Describe(descs)
	p.size.Describe(descs)
	p.usagePct.Describe(descs)
	p.lost.Describe(descs)
}

// Collect implements prometheus.Collector.Collect
func (p *perfUsageCollector) Collect(metrics chan<- prometheus.Metric) {
	p.usage.Collect(metrics)
	p.size.Collect(metrics)
	p.usagePct.Collect(metrics)
	p.lost.Collect(metrics)

	// reset usage and percentage to zero, so lack of callback doesn't report as continuous usage
	p.usage.reset()
	p.usagePct.reset()
	// Do not reset `size`, so its value is always available. It should not change its value once set.
}

type mapMetric struct {
	mapType   string
	perCPUMax map[int]float64
}

type maxGauge struct {
	gv  *prometheus.GaugeVec
	cur map[string]*mapMetric
}

func newMaxGauge(gv *prometheus.GaugeVec) *maxGauge {
	return &maxGauge{gv: gv, cur: make(map[string]*mapMetric)}
}

func (f *maxGauge) set(mapName string, mapType string, cpu int, val float64) {
	metric, ok := f.cur[mapName]
	if !ok {
		metric = &mapMetric{
			mapType:   mapType,
			perCPUMax: make(map[int]float64),
		}
		f.cur[mapName] = metric
	}

	cur := metric.perCPUMax[cpu]
	if val >= cur {
		metric.perCPUMax[cpu] = val
		f.gv.WithLabelValues(mapName, mapType, strconv.Itoa(cpu)).Set(val)
	}
}

func (f *maxGauge) reset() {
	for _, metric := range f.cur {
		for cpu := range metric.perCPUMax {
			metric.perCPUMax[cpu] = 0
		}
	}
}

func (f *maxGauge) get(mapName string, cpu int) float64 {
	metric, ok := f.cur[mapName]
	if !ok {
		return 0
	}
	return metric.perCPUMax[cpu]
}

// Describe implements prometheus.Collector.Describe
func (f *maxGauge) Describe(descs chan<- *prometheus.Desc) {
	f.gv.Describe(descs)
}

// Collect implements prometheus.Collector.Collect
func (f *maxGauge) Collect(metrics chan<- prometheus.Metric) {
	for mapName, metric := range f.cur {
		for cpu := range metric.perCPUMax {
			// if no values reported in this interval, use 0
			if metric.perCPUMax[cpu] == 0 {
				f.gv.WithLabelValues(mapName, metric.mapType, strconv.Itoa(cpu)).Set(0)
			}
		}
	}
	f.gv.Collect(metrics)
}
