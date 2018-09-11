// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/chennqqi/gohbase (interfaces: AdminClient)

package mock

import (
	gomock "github.com/golang/mock/gomock"
	hrpc "github.com/chennqqi/gohbase/hrpc"
	pb "github.com/chennqqi/gohbase/pb"
	reflect "reflect"
)

// MockAdminClient is a mock of AdminClient interface
type MockAdminClient struct {
	ctrl     *gomock.Controller
	recorder *MockAdminClientMockRecorder
}

// MockAdminClientMockRecorder is the mock recorder for MockAdminClient
type MockAdminClientMockRecorder struct {
	mock *MockAdminClient
}

// NewMockAdminClient creates a new mock instance
func NewMockAdminClient(ctrl *gomock.Controller) *MockAdminClient {
	mock := &MockAdminClient{ctrl: ctrl}
	mock.recorder = &MockAdminClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (_m *MockAdminClient) EXPECT() *MockAdminClientMockRecorder {
	return _m.recorder
}

// ClusterStatus mocks base method
func (_m *MockAdminClient) ClusterStatus() (*pb.ClusterStatus, error) {
	ret := _m.ctrl.Call(_m, "ClusterStatus")
	ret0, _ := ret[0].(*pb.ClusterStatus)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ClusterStatus indicates an expected call of ClusterStatus
func (_mr *MockAdminClientMockRecorder) ClusterStatus() *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "ClusterStatus", reflect.TypeOf((*MockAdminClient)(nil).ClusterStatus))
}

// CreateTable mocks base method
func (_m *MockAdminClient) CreateTable(_param0 *hrpc.CreateTable) error {
	ret := _m.ctrl.Call(_m, "CreateTable", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateTable indicates an expected call of CreateTable
func (_mr *MockAdminClientMockRecorder) CreateTable(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "CreateTable", reflect.TypeOf((*MockAdminClient)(nil).CreateTable), arg0)
}

// DeleteTable mocks base method
func (_m *MockAdminClient) DeleteTable(_param0 *hrpc.DeleteTable) error {
	ret := _m.ctrl.Call(_m, "DeleteTable", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteTable indicates an expected call of DeleteTable
func (_mr *MockAdminClientMockRecorder) DeleteTable(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "DeleteTable", reflect.TypeOf((*MockAdminClient)(nil).DeleteTable), arg0)
}

// DisableTable mocks base method
func (_m *MockAdminClient) DisableTable(_param0 *hrpc.DisableTable) error {
	ret := _m.ctrl.Call(_m, "DisableTable", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

// DisableTable indicates an expected call of DisableTable
func (_mr *MockAdminClientMockRecorder) DisableTable(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "DisableTable", reflect.TypeOf((*MockAdminClient)(nil).DisableTable), arg0)
}

// EnableTable mocks base method
func (_m *MockAdminClient) EnableTable(_param0 *hrpc.EnableTable) error {
	ret := _m.ctrl.Call(_m, "EnableTable", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

// EnableTable indicates an expected call of EnableTable
func (_mr *MockAdminClientMockRecorder) EnableTable(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "EnableTable", reflect.TypeOf((*MockAdminClient)(nil).EnableTable), arg0)
}
