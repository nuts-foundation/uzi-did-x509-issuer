// Code generated by MockGen. DO NOT EDIT.
// Source: uzi_vc_issuer/pem_reader.go
//
// Generated by this command:
//
//	mockgen -destination=uzi_vc_issuer/pem_reader_mock.go -package=uzi_vc_issuer -source=uzi_vc_issuer/pem_reader.go
//

// Package uzi_vc_issuer is a generated GoMock package.
package pem

import (
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockPemReader is a mock of PemReader interface.
type MockPemReader struct {
	ctrl     *gomock.Controller
	recorder *MockPemReaderMockRecorder
}

// MockPemReaderMockRecorder is the mock recorder for MockPemReader.
type MockPemReaderMockRecorder struct {
	mock *MockPemReader
}

// NewMockPemReader creates a new mock instance.
func NewMockPemReader(ctrl *gomock.Controller) *MockPemReader {
	mock := &MockPemReader{ctrl: ctrl}
	mock.recorder = &MockPemReaderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPemReader) EXPECT() *MockPemReaderMockRecorder {
	return m.recorder
}

// ParseFileOrPath mocks base method.
func (m *MockPemReader) ParseFileOrPath(path, pemType string) (*[][]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ParseFileOrPath", path, pemType)
	ret0, _ := ret[0].(*[][]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ParseFileOrPath indicates an expected call of ParseFileOrPath.
func (mr *MockPemReaderMockRecorder) ParseFileOrPath(path, pemType any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ParseFileOrPath", reflect.TypeOf((*MockPemReader)(nil).ParseFileOrPath), path, pemType)
}