// Code generated by MockGen. DO NOT EDIT.
// Source: network_linux.go

// Package core is a generated GoMock package.
package core

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockNetworkCollector is a mock of NetworkCollector interface.
type MockNetworkCollector struct {
	ctrl     *gomock.Controller
	recorder *MockNetworkCollectorMockRecorder
}

// MockNetworkCollectorMockRecorder is the mock recorder for MockNetworkCollector.
type MockNetworkCollectorMockRecorder struct {
	mock *MockNetworkCollector
}

// NewMockNetworkCollector creates a new mock instance.
func NewMockNetworkCollector(ctrl *gomock.Controller) *MockNetworkCollector {
	mock := &MockNetworkCollector{ctrl: ctrl}
	mock.recorder = &MockNetworkCollectorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockNetworkCollector) EXPECT() *MockNetworkCollectorMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockNetworkCollector) Close() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Close")
}

// Close indicates an expected call of Close.
func (mr *MockNetworkCollectorMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockNetworkCollector)(nil).Close))
}

// GetStats mocks base method.
func (m *MockNetworkCollector) GetStats(pids PidSet) (map[uint32]NetworkStats, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetStats", pids)
	ret0, _ := ret[0].(map[uint32]NetworkStats)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetStats indicates an expected call of GetStats.
func (mr *MockNetworkCollectorMockRecorder) GetStats(pids interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetStats", reflect.TypeOf((*MockNetworkCollector)(nil).GetStats), pids)
}
