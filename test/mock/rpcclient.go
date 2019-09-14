// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/tsuna/gohbase (interfaces: RPCClient)

package mock

import (
	gomock "github.com/golang/mock/gomock"
	proto "github.com/golang/protobuf/proto"
	hrpc "github.com/tsuna/gohbase/hrpc"
	reflect "reflect"
)

// MockRPCClient is a mock of RPCClient interface
type MockRPCClient struct {
	ctrl     *gomock.Controller
	recorder *MockRPCClientMockRecorder
}

// MockRPCClientMockRecorder is the mock recorder for MockRPCClient
type MockRPCClientMockRecorder struct {
	mock *MockRPCClient
}

// NewMockRPCClient creates a new mock instance
func NewMockRPCClient(ctrl *gomock.Controller) *MockRPCClient {
	mock := &MockRPCClient{ctrl: ctrl}
	mock.recorder = &MockRPCClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (_m *MockRPCClient) EXPECT() *MockRPCClientMockRecorder {
	return _m.recorder
}

// SendRPC mocks base method
func (_m *MockRPCClient) SendRPC(_param0 hrpc.Call) (proto.Message, error) {
	ret := _m.ctrl.Call(_m, "SendRPC", _param0)
	ret0, _ := ret[0].(proto.Message)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SendRPC indicates an expected call of SendRPC
func (_mr *MockRPCClientMockRecorder) SendRPC(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "SendRPC", reflect.TypeOf((*MockRPCClient)(nil).SendRPC), arg0)
}
