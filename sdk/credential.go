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
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Azure/azure-pipeline-go/pipeline"
)

// Credential represent any credential type; it is used to create a credential policy Factory.
type Credential interface {
	pipeline.Factory
	credentialMarker()
}

// TokenCredential represents a token credential (which is also a pipeline.Factory).
type TokenCredential interface {
	Credential
	Token() string
	SetToken(newToken string)
}

// NewTokenCredential creates a token credential for use with role-based access control (RBAC) access to Azure Storage
// resources. You initialize the TokenCredential with an initial token value. If you pass a non-nil value for
// tokenRefresher, then the function you pass will be called immediately (so it can refresh and change the
// TokenCredential's token value by calling SetToken; your tokenRefresher function must return a time.Duration
// indicating how long the TokenCredential object should wait before calling your tokenRefresher function again.
func NewTokenCredential(initialToken string, tokenRefresher func(credential TokenCredential) time.Duration) TokenCredential {
	tc := &tokenCredential{}
	tc.SetToken(initialToken) // We dont' set it above to guarantee atomicity
	if tokenRefresher == nil {
		return tc // If no callback specified, return the simple tokenCredential
	}

	tcwr := &tokenCredentialWithRefresh{token: tc}
	tcwr.token.startRefresh(tokenRefresher)
	runtime.SetFinalizer(tcwr, func(deadTC *tokenCredentialWithRefresh) {
		deadTC.token.stopRefresh()
		deadTC.token = nil //  Sanity (not really required)
	})
	return tcwr
}

// tokenCredentialWithRefresh is a wrapper over a token credential.
// When this wrapper object gets GC'd, it stops the tokenCredential's timer
// which allows the tokenCredential object to also be GC'd.
type tokenCredentialWithRefresh struct {
	token *tokenCredential
}

// credentialMarker is a package-internal method that exists just to satisfy the Credential interface.
func (*tokenCredentialWithRefresh) credentialMarker() {}

// Token returns the current token value
func (f *tokenCredentialWithRefresh) Token() string { return f.token.Token() }

// SetToken changes the current token value
func (f *tokenCredentialWithRefresh) SetToken(token string) { f.token.SetToken(token) }

// New satisfies pipeline.Factory's New method creating a pipeline policy object.
func (f *tokenCredentialWithRefresh) New(next pipeline.Policy, po *pipeline.PolicyOptions) pipeline.Policy {
	return f.token.New(next, po)
}

///////////////////////////////////////////////////////////////////////////////

// tokenCredential is a pipeline.Factory is the credential's policy factory.
type tokenCredential struct {
	token atomic.Value

	// The members below are only used if the user specified a tokenRefresher callback function.
	timer          *time.Timer
	tokenRefresher func(c TokenCredential) time.Duration
	lock           sync.Mutex
	stopped        bool
}

// credentialMarker is a package-internal method that exists just to satisfy the Credential interface.
func (*tokenCredential) credentialMarker() {}

// Token returns the current token value
func (tc *tokenCredential) Token() string { return tc.token.Load().(string) }

// SetToken changes the current token value
func (tc *tokenCredential) SetToken(token string) { tc.token.Store(token) }

// startRefresh calls refresh which immediately calls tokenRefresher
// and then starts a timer to call tokenRefresher in the future.
func (tc *tokenCredential) startRefresh(tokenRefresher func(c TokenCredential) time.Duration) {
	tc.tokenRefresher = tokenRefresher
	tc.stopped = false // In case user calls StartRefresh, StopRefresh, & then StartRefresh again
	tc.refresh()
}

// refresh calls the user's tokenRefresher so they can refresh the token (by
// calling SetToken) and then starts another time (based on the returned duration)
// in order to refresh the token again in the future.
func (tc *tokenCredential) refresh() {
	d := tc.tokenRefresher(tc) // Invoke the user's refresh callback outside of the lock
	tc.lock.Lock()
	if !tc.stopped && d > 0 {
		tc.timer = time.AfterFunc(d, tc.refresh)
	}
	tc.lock.Unlock()
}

// stopRefresh stops any pending timer and sets stopped field to true to prevent
// any new timer from starting.
// NOTE: Stopping the timer allows the GC to destroy the tokenCredential object.
func (tc *tokenCredential) stopRefresh() {
	tc.lock.Lock()
	tc.stopped = true
	if tc.timer != nil {
		tc.timer.Stop()
	}
	tc.lock.Unlock()
}

func (tc *tokenCredential) New(next pipeline.Policy, o *pipeline.PolicyOptions) pipeline.Policy {
	return pipeline.PolicyFunc(func(ctx context.Context, req pipeline.Request) (pipeline.Response, error) {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tc.Token()))
		return next.Do(ctx, req)
	})
}
