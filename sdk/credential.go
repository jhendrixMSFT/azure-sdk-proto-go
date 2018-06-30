package sdk

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

	"github.com/Azure/azure-pipeline-go/pipeline"
	"github.com/jhendrixMSFT/adal-proto-go/adal"
)

// Credential represent any credential type; it is used to create a credential policy Factory.
type Credential interface {
	pipeline.Factory
	credentialMarker()
}

func NewTokenCredential(t adal.Token) Credential {
	return &tokenCredential{t: t}
}

type tokenCredential struct {
	t adal.Token
}

func (tc tokenCredential) New(next pipeline.Policy, o *pipeline.PolicyOptions) pipeline.Policy {
	return pipeline.PolicyFunc(func(ctx context.Context, req pipeline.Request) (pipeline.Response, error) {
		req.Header.Add("Authorization", tc.t.AuthorizationHeader())
		return next.Do(ctx, req)
	})
}

func (tokenCredential) credentialMarker() {}
