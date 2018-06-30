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
	"github.com/Azure/azure-pipeline-go/pipeline"
	"github.com/jhendrixMSFT/policy-proto-go/policy"
)

func NewDefaultPipeline(c Credential) pipeline.Pipeline {
	if c == nil {
		panic("c can't be nil")
	}
	f := []pipeline.Factory{
		policy.NewUserAgentPolicyFactory(),
		policy.NewResourceProviderRegistrar(),
		policy.NewSimpleRetryPolicyFactory(policy.SimpleRetryPolicyConfig{}),
		c,
		pipeline.MethodFactoryMarker(),
	}
	return pipeline.NewPipeline(f, pipeline.Options{HTTPSender: policy.NewHTTPSenderWithCookiesFactory()})
}
