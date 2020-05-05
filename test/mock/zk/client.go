// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/tsuna/gohbase/zk (interfaces: Client)

package mock

import (
	gomock "github.com/golang/mock/gomock"
	zk "github.com/chennqqi/gohbase/zk"
	reflect "reflect"
)

// MockClient is a mock of Client interface
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
}

// MockClientMockRecorder is the mock recorder for MockClient
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (_m *MockClient) EXPECT() *MockClientMockRecorder {
	return _m.recorder
}

// LocateResource mocks base method
func (_m *MockClient) LocateResource(_param0 zk.ResourceName) (string, error) {
	ret := _m.ctrl.Call(_m, "LocateResource", _param0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LocateResource indicates an expected call of LocateResource
func (_mr *MockClientMockRecorder) LocateResource(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "LocateResource", reflect.TypeOf((*MockClient)(nil).LocateResource), arg0)
}
