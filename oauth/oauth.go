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
	"fmt"
	"net/url"

	"github.com/jhendrixMSFT/azure-sdk-proto-go/oauth/internal"
)

const (
	// V2Endpoint is the URL for OAuth 2.0 authorization.
	V2Endpoint       = "https://login.microsoftonline.com/"
	endpointTemplate = "%s/oauth2/%s?api-version=%s"
)

// A Authorizor is an OAuth authorization endpoint.
type Authorizor interface {
	Endpoint() *url.URL
}

///////////////////////////////////////////////////////////////////////////////

type tokenAuthorizor struct {
	u *url.URL
}

func (ta tokenAuthorizor) Endpoint() *url.URL {
	return ta.u
}

// NewTokenAuthorizor creates an authorizor that uses the token endpoint.
func NewTokenAuthorizor(endpointURL string, options ...Option) (Authorizor, error) {
	u, err := url.Parse(endpointURL)
	if err != nil {
		return nil, err
	}
	settings := &internal.Settings{}
	for _, option := range options {
		option.Apply(settings)
	}
	// if no API version was specified default to 1.0
	if settings.APIVersion == "" {
		settings.APIVersion = "1.0"
	}
	u, err = u.Parse(fmt.Sprintf(endpointTemplate, settings.TenantID, "token", settings.APIVersion))
	if err != nil {
		return nil, err
	}
	return tokenAuthorizor{u: u}, nil
}

///////////////////////////////////////////////////////////////////////////////

// A Option is an option for configuring an authorizor.
type Option interface {
	Apply(*internal.Settings)
}

// WithAPIVersion returns an OAuthOption that specifies an OAuth API version.
func WithAPIVersion(apiVer string) Option {
	return withAPIVersion(apiVer)
}

type withAPIVersion string

func (w withAPIVersion) Apply(s *internal.Settings) {
	s.APIVersion = string(w)
}

// WithTenantID returns an OAuthOption that specifies a tenant ID.
func WithTenantID(tenantID string) Option {
	return withTenantID(tenantID)
}

type withTenantID string

func (w withTenantID) Apply(s *internal.Settings) {
	s.TenantID = string(w)
}
