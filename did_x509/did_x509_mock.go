// Code generated by MockGen. DO NOT EDIT.
// Source: did_x509/did_x509.go
//
// Generated by this command:
//
//	mockgen -destination=did_x509/did_x509_mock.go -package=did_x509 -source=did_x509/did_x509.go
//

// Package did_x509 is a generated GoMock package.
package did_x509

import (
	x509 "crypto/x509"
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockDidCreator is a mock of DidCreator interface.
type MockDidCreator struct {
	ctrl     *gomock.Controller
	recorder *MockDidCreatorMockRecorder
}

// MockDidCreatorMockRecorder is the mock recorder for MockDidCreator.
type MockDidCreatorMockRecorder struct {
	mock *MockDidCreator
}

// NewMockDidCreator creates a new mock instance.
func NewMockDidCreator(ctrl *gomock.Controller) *MockDidCreator {
	mock := &MockDidCreator{ctrl: ctrl}
	mock.recorder = &MockDidCreatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDidCreator) EXPECT() *MockDidCreatorMockRecorder {
	return m.recorder
}

// CreateDid mocks base method.
func (m *MockDidCreator) CreateDid(chain *[]x509.Certificate) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateDid", chain)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateDid indicates an expected call of CreateDid.
func (mr *MockDidCreatorMockRecorder) CreateDid(chain any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateDid", reflect.TypeOf((*MockDidCreator)(nil).CreateDid), chain)
}
