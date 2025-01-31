// The MIT License
//
// Copyright (c) 2020 Temporal Technologies Inc.  All rights reserved.
//
// Copyright (c) 2020 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

//go:generate mockgen -copyright_file ../../LICENSE -package $GOPACKAGE -source $GOFILE -destination claim_mapper_mock.go

package authorization

import (
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"strings"

	"go.temporal.io/server/common/config"
	"go.temporal.io/server/common/log"
	"go.temporal.io/server/common/log/tag"
	"google.golang.org/grpc/credentials"
)

// @@@SNIPSTART temporal-common-authorization-authinfo
// Authentication information from subject's JWT token or/and mTLS certificate
type AuthInfo struct {
	AuthToken     string
	TLSSubject    *pkix.Name
	TLSConnection *credentials.TLSInfo
	ExtraData     string
	Audience      string
}

// @@@SNIPEND

// @@@SNIPSTART temporal-common-authorization-claimmapper-interface
// ClaimMapper converts authorization info of a subject into Temporal claims (permissions) for authorization
type ClaimMapper interface {
	GetClaims(authInfo *AuthInfo) (*Claims, error)
}

// @@@SNIPEND

// Normally, GetClaims will never be called without either an auth token or TLS metadata set in
// AuthInfo. However, if you want your ClaimMapper to be called in all cases, you can implement
// this additional interface and return false.
type ClaimMapperWithAuthInfoRequired interface {
	AuthInfoRequired() bool
}

// No-op claim mapper that gives system level admin permission to everybody
type noopClaimMapper struct{}

var _ ClaimMapper = (*noopClaimMapper)(nil)
var _ ClaimMapperWithAuthInfoRequired = (*noopClaimMapper)(nil)

func NewNoopClaimMapper() ClaimMapper {
	return &noopClaimMapper{}
}

func (*noopClaimMapper) GetClaims(_ *AuthInfo) (*Claims, error) {
	return &Claims{System: RoleAdmin}, nil
}

// This implementation can run even without auth info.
func (*noopClaimMapper) AuthInfoRequired() bool {
	return false
}

var (
	ErrUnknownClaimMapper = errors.New("unknown claim mapper")
)

func GetClaimMapperFromConfig(authConfig *config.Authorization, logger log.Logger) (ClaimMapper, error) {
	logger.Debug("Getting claim mapper from config", tag.NewAnyTag("config", authConfig))

	switch strings.ToLower(authConfig.ClaimMapper) {
	case "":
		logger.Debug("No claim mapper specified, using NoopClaimMapper")
		return NewNoopClaimMapper(), nil
	case "default":
		logger.Debug("Default claim mapper specified, using DefaultJWTClaimMapper")
		return NewDefaultJWTClaimMapper(NewDefaultTokenKeyProvider(authConfig, logger), authConfig, logger), nil
	}
	err := fmt.Errorf("%w: %s", ErrUnknownClaimMapper, authConfig.ClaimMapper)
	logger.Error("Unknown claim mapper", tag.Error(err))
	return nil, err
}
