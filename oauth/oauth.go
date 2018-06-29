package oauth

// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"context"
	"fmt"
	"net/url"

	"github.com/Azure/azure-pipeline-go/pipeline"
	"github.com/jhendrixMSFT/azure-sdk-proto-go/oauth/internal"
)

// Authority is an authorization URL endpoint.
type Authority string

const (
	// V2Endpoint is the URL for OAuth 2.0 authorization.
	V2Endpoint       = Authority("https://login.microsoftonline.com/")
	endpointTemplate = "%s/oauth2/%s?api-version=%s"
)

// AuthenticationContext is used to retrieve authentication tokens from AAD and ADFS.
type AuthenticationContext interface {
	AcquireTokenFromClientCredentials(ctx context.Context, clientID, secret, resource string) (Token, error)
}

///////////////////////////////////////////////////////////////////////////////

type authCtx struct {
	u *url.URL
	p pipeline.Pipeline
}

func (ta authCtx) AcquireTokenFromClientCredentials(ctx context.Context, resource, clientID, secret string) (Token, error) {
	c := clientCredentials{
		ep:  ta.u,
		cid: clientID,
		sec: secret,
		res: resource,
	}
	return c.acquire(ctx, ta.p)
}

// NewAuthenticationContext creates a context using the specified authority, pipeline, and options.
func NewAuthenticationContext(authority Authority, p pipeline.Pipeline, options ...AuthOption) (AuthenticationContext, error) {
	if p == nil {
		panic("p can't be nil")
	}
	u, err := url.Parse(string(authority))
	if err != nil {
		return nil, err
	}
	settings := &internal.AuthSettings{}
	for _, option := range options {
		option.Apply(settings)
	}
	// if no API version was specified default to 1.0
	if settings.APIVersion == "" {
		settings.APIVersion = "1.0"
	}
	// if no endpoint was specified default to token
	if settings.Endpoint == "" {
		settings.Endpoint = "token"
	}
	u, err = u.Parse(fmt.Sprintf(endpointTemplate, settings.TenantID, settings.Endpoint, settings.APIVersion))
	if err != nil {
		return nil, err
	}
	return authCtx{u: u, p: p}, nil
}

///////////////////////////////////////////////////////////////////////////////

// A AuthOption is an option for configuring an authentication context.
type AuthOption interface {
	Apply(*internal.AuthSettings)
}

// WithAPIVersion returns an OAuthOption that specifies an OAuth API version.
func WithAPIVersion(apiVer string) AuthOption {
	return withAPIVersion(apiVer)
}

type withAPIVersion string

func (w withAPIVersion) Apply(s *internal.AuthSettings) {
	s.APIVersion = string(w)
}

// WithEndpoint returns an OAuthOption that specifies the authorization endpoint.
func WithEndpoint(endpoint string) AuthOption {
	return withEndpoint(endpoint)
}

type withEndpoint string

func (w withEndpoint) Apply(s *internal.AuthSettings) {
	s.Endpoint = string(w)
}

// WithTenantID returns an OAuthOption that specifies a tenant ID.
func WithTenantID(tenantID string) AuthOption {
	return withTenantID(tenantID)
}

type withTenantID string

func (w withTenantID) Apply(s *internal.AuthSettings) {
	s.TenantID = string(w)
}
