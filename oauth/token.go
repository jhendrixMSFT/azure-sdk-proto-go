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
	"net/http"
	"strconv"
	"time"
)

// Token represents the results of one token acquisition operation.
type Token interface {
	IsExpired() bool
	Value() string
}

type accessToken struct {
	rawResp     *http.Response
	AccessToken string `json:"access_token"`
	ExpiresIn   string `json:"expires_in"`
	ExpiresOn   string `json:"expires_on"`
	NotBefore   string `json:"not_before"`
	Resource    string `json:"resource"`
	Type        string `json:"token_type"`
}

func (at accessToken) IsExpired() bool {
	i, err := strconv.ParseInt(at.ExpiresOn, 10, 64)
	if err != nil {
		panic(fmt.Sprintf("failed to parse 'ExpiresOn': %v", err))
	}
	t := time.Unix(i, 0)
	return time.Now().After(t)
}

func (at accessToken) Response() *http.Response {
	return at.rawResp
}

func (at accessToken) Value() string {
	return at.AccessToken
}
