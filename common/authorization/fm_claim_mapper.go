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

package authorization

import (
	"context"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/server/common/config"
	"go.temporal.io/server/common/log"
	"go.temporal.io/server/common/log/tag"
	"go.temporal.io/server/common/primitives"
)

const (
	defaultPermissionsClaimNameFM = "permissions"
	authorizationBearerFM         = "bearer"
	headerSubjectFM               = "sub"
	permissionScopeSystemFM       = primitives.SystemLocalNamespace
	permissionReadFM              = "read"
	permissionWriteFM             = "write"
	permissionWorkerFM            = "worker"
	permissionAdminFM             = "admin"
)

// Default claim mapper that gives system level admin permission to everybody
type fairmoneyClaimMapper struct {
	keyProvider          TokenKeyProvider
	logger               log.Logger
	permissionsClaimName string
}

func NewFMClaimMapper(provider TokenKeyProvider, cfg *config.Authorization, logger log.Logger) ClaimMapper {
	claimName := cfg.PermissionsClaimName
	if claimName == "" {
		claimName = defaultPermissionsClaimNameFM
	}
	logger.Debug("Creating new default JWT claim mapper", tag.NewAnyTag("claimName", claimName))
	return &fairmoneyClaimMapper{keyProvider: provider, logger: logger, permissionsClaimName: claimName}
}

var _ ClaimMapper = (*fairmoneyClaimMapper)(nil)

func convertToInterfaceSlice(strs []string) []interface{} {
    result := make([]interface{}, len(strs))
    for i, v := range strs {
        result[i] = v
    }
    return result
}

func (a *fairmoneyClaimMapper) GetClaims(authInfo *AuthInfo) (*Claims, error) {
	a.logger.Debug("Getting claims from authInfo")

	claims := Claims{}

    // extract claims from tsl-subect (field Organization) if any
    // tlsOrg := convertToInterfaceSlice(authInfo.TLSSubject.Organization)
    if authInfo.TLSConnection != nil {
        a.logger.Debug("Getting organizational units from tsl cert", tag.NewAnyTag("organizationalUnits", authInfo.TLSSubject.OrganizationalUnit))

        rawClaims := convertToInterfaceSlice(authInfo.TLSSubject.OrganizationalUnit)
        err := a.extractPermissions(rawClaims, &claims)
        if err != nil {
            a.logger.Error("Error extracting tls permissions", tag.Error(err))
            return nil, err
        }
    }
    if authInfo.AuthToken != "" {
        parts := strings.Split(authInfo.AuthToken, " ")

        if len(parts) != 2 {
            a.logger.Error("Unexpected authorization token format", tag.NewAnyTag("authToken", authInfo.AuthToken))
            return nil, serviceerror.NewPermissionDenied("unexpected authorization token format", "")
        }
        if !strings.EqualFold(parts[0], authorizationBearerFM) {
            a.logger.Error("Unexpected name in authorization token", tag.NewAnyTag("authToken", authInfo.AuthToken))
            return nil, serviceerror.NewPermissionDenied("unexpected name in authorization token", "")
        }
        jwtClaims, err := parseJWTWithAudienceFM(parts[1], a.keyProvider, authInfo.Audience)
        if err != nil {
            a.logger.Error("Error parsing JWT with audience", tag.Error(err))
            return nil, err
        }
        subject, ok := jwtClaims[headerSubject].(string)
        if !ok {
            a.logger.Error("Unexpected value type of \"sub\" claim", tag.NewAnyTag("jwtClaims", jwtClaims))
            return nil, serviceerror.NewPermissionDenied("unexpected value type of \"sub\" claim", "")
        }
        claims.Subject = subject
        permissions, ok := jwtClaims[a.permissionsClaimName].([]interface{})
        if ok {
            err := a.extractPermissions(permissions, &claims)
            if err != nil {
                a.logger.Error("Error extracting permissions", tag.Error(err))
                return nil, err
            }
        }
        a.logger.Debug("Claims obtained", tag.NewAnyTag("claims", claims))
    }

    return &claims, nil
}

func (a *fairmoneyClaimMapper) extractPermissions(permissions []interface{}, claims *Claims) error {
	a.logger.Debug("Extracting permissions", tag.NewAnyTag("permissions", permissions))

	for _, permission := range permissions {
		p, ok := permission.(string)
		if !ok {
			a.logger.Warn(fmt.Sprintf("Ignoring permission that is not a string: %v", permission))
			continue
		}
		parts := strings.Split(p, ":")
		if len(parts) != 3 {
			a.logger.Warn(fmt.Sprintf("Ignoring permission in unexpected format: %v", permission))
			continue
		}
		if parts[0] != "temporal" {
            a.logger.Warn(fmt.Sprintf("Ignoring permission not prefixed with 'temporal:': %v", permission))
			continue
		}
		namespace := parts[1]
		if namespace == permissionScopeSystemFM {
			claims.System |= permissionToRoleFM(parts[2])
		} else {
			if claims.Namespaces == nil {
				claims.Namespaces = make(map[string]Role)
			}
			role := claims.Namespaces[namespace]
			role |= permissionToRoleFM(parts[2])
			claims.Namespaces[namespace] = role
		}
	}
	a.logger.Debug("Permissions extracted", tag.NewAnyTag("claims", claims))
	return nil
}

func parseJWTFM(tokenString string, keyProvider TokenKeyProvider) (jwt.MapClaims, error) {
	return parseJWTWithAudienceFM(tokenString, keyProvider, "")
}

func parseJWTWithAudienceFM(tokenString string, keyProvider TokenKeyProvider, audience string) (jwt.MapClaims, error) {
	parser := jwt.NewParser(jwt.WithValidMethods(keyProvider.SupportedMethods()))
	var keyFunc jwt.Keyfunc

	if provider, _ := keyProvider.(RawTokenKeyProvider); provider != nil {
		keyFunc = func(token *jwt.Token) (interface{}, error) {
			// reserve context
			// impl may introduce network request to get public key
			return provider.GetKey(context.Background(), token)
		}
	} else {
		keyFunc = func(token *jwt.Token) (interface{}, error) {
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("malformed token - no \"kid\" header")
			}
			alg := token.Header["alg"].(string)
			switch token.Method.(type) {
			case *jwt.SigningMethodHMAC:
				return keyProvider.HmacKey(alg, kid)
			case *jwt.SigningMethodRSA:
				return keyProvider.RsaKey(alg, kid)
			case *jwt.SigningMethodECDSA:
				return keyProvider.EcdsaKey(alg, kid)
			default:
				return nil, serviceerror.NewPermissionDenied(
					fmt.Sprintf("unexpected signing method: %v for algorithm: %v", token.Method, token.Header["alg"]), "")
			}
		}
	}

	token, err := parser.Parse(tokenString, keyFunc)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, serviceerror.NewPermissionDenied("invalid token with no claims", "")
	}
	if err := claims.Valid(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(audience) != "" && !claims.VerifyAudience(audience, true) {
		return nil, serviceerror.NewPermissionDenied("audience mismatch", "")
	}
	return claims, nil
}

func permissionToRoleFM(permission string) Role {
	switch strings.ToLower(permission) {
	case permissionReadFM:
		return RoleReader
	case permissionWriteFM:
		return RoleWriter
	case permissionAdminFM:
		return RoleAdmin
	case permissionWorkerFM:
		return RoleWorker
	}
	return RoleUndefined
}
