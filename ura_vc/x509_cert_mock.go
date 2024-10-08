// Code generated by MockGen. DO NOT EDIT.
// Source: ura_vc/x509_cert.go
//
// Generated by this command:
//
//	mockgen -destination=ura_vc/x509_cert_mock.go -package=ura_vc -source=ura_vc/x509_cert.go
//

// Package ura_vc is a generated GoMock package.
package ura_vc

import (
	x509 "crypto/x509"
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockChainParser is a mock of ChainParser interface.
type MockChainParser struct {
	ctrl     *gomock.Controller
	recorder *MockChainParserMockRecorder
}

// MockChainParserMockRecorder is the mock recorder for MockChainParser.
type MockChainParserMockRecorder struct {
	mock *MockChainParser
}

// NewMockChainParser creates a new mock instance.
func NewMockChainParser(ctrl *gomock.Controller) *MockChainParser {
	mock := &MockChainParser{ctrl: ctrl}
	mock.recorder = &MockChainParserMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockChainParser) EXPECT() *MockChainParserMockRecorder {
	return m.recorder
}

// ParseCertificates mocks base method.
func (m *MockChainParser) ParseCertificates(derChain *[][]byte) (*[]x509.Certificate, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ParseCertificates", derChain)
	ret0, _ := ret[0].(*[]x509.Certificate)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ParseCertificates indicates an expected call of ParseCertificates.
func (mr *MockChainParserMockRecorder) ParseCertificates(derChain any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ParseCertificates", reflect.TypeOf((*MockChainParser)(nil).ParseCertificates), derChain)
}