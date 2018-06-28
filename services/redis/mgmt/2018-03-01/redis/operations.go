package redis

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
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"context"
	"net/http"
	"net/url"

	"github.com/Azure/azure-pipeline-go/pipeline"
)

// OperationsClient is the REST API for Azure Redis Cache Service.
type OperationsClient struct {
	BaseClient
}

// NewOperationsClient creates an instance of the OperationsClient client.
func NewOperationsClient(subscriptionID string, p pipeline.Pipeline) OperationsClient {
	return OperationsClient{NewBaseClient(subscriptionID, p)}
}

// NewOperationsClientWithBaseURI creates an instance of the OperationsClient client.
func NewOperationsClientWithBaseURI(u url.URL, subscriptionID string, p pipeline.Pipeline) OperationsClient {
	return OperationsClient{NewBaseClientWithURI(u, subscriptionID, p)}
}

// List lists all of the available REST API operations of the Microsoft.Cache provider.
func (client OperationsClient) List(ctx context.Context) (result OperationListResultPage, err error) {
	/*result.fn = client.listNextResults
	req, err := client.ListPreparer(ctx)
	if err != nil {
		err = autorest.NewErrorWithError(err, "redis.OperationsClient", "List", nil, "Failure preparing request")
		return
	}

	resp, err := client.ListSender(req)
	if err != nil {
		result.olr.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "redis.OperationsClient", "List", resp, "Failure sending request")
		return
	}

	result.olr, err = client.ListResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "redis.OperationsClient", "List", resp, "Failure responding to request")
	}*/

	return
}

// ListPreparer prepares the List request.
func (client OperationsClient) listPreparer(ctx context.Context) (*http.Request, error) {
	/*const APIVersion = "2018-03-01"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPath("/providers/Microsoft.Cache/operations"),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))*/
	return nil, nil
}

// ListResponder handles the response to the List request. The method always
// closes the http.Response Body.
func (client OperationsClient) listResponder(resp *http.Response) (result OperationListResult, err error) {
	/*err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}*/
	return
}

// listNextResults retrieves the next set of results, if any.
func (client OperationsClient) listNextResults(lastResults OperationListResult) (result OperationListResult, err error) {
	/*req, err := lastResults.operationListResultPreparer()
	if err != nil {
		return result, autorest.NewErrorWithError(err, "redis.OperationsClient", "listNextResults", nil, "Failure preparing next results request")
	}
	if req == nil {
		return
	}
	resp, err := client.ListSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		return result, autorest.NewErrorWithError(err, "redis.OperationsClient", "listNextResults", resp, "Failure sending next results request")
	}
	result, err = client.ListResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "redis.OperationsClient", "listNextResults", resp, "Failure responding to next results request")
	}*/
	return
}

// ListComplete enumerates all values, automatically crossing page boundaries as required.
func (client OperationsClient) ListComplete(ctx context.Context) (result OperationListResultIterator, err error) {
	//result.page, err = client.List(ctx)
	return
}
