package api

import (
	"encoding/json"
	"errors"
	"github.com/google/go-querystring/query"
	"github.com/hashicorp/go-retryablehttp"
	"gitlab.com/code-secure/analyzer/finding"
	"gitlab.com/code-secure/analyzer/logger"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Client struct {
	baseURL    *url.URL
	apiKey     string
	httpClient *retryablehttp.Client
	UserAgent  string
}

func NewClient(server string, apiKey string) (*Client, error) {
	client := &Client{
		apiKey:     apiKey,
		httpClient: retryablehttp.NewClient(),
	}
	err := client.setBaseURL(server)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (client *Client) TestConnection() bool {
	req, err := client.newRequest(http.MethodGet, "api/ci/ping", nil)
	if err != nil {
		logger.Error(err.Error())
		return false
	}
	res, err := client.do(req, nil)
	if err != nil {
		logger.Error(err.Error())
		return false
	}
	if res.StatusCode == 403 || res.StatusCode == 401 {
		logger.Error("Token is invalid")
		return false
	}
	return res.StatusCode == 200
}

func (client *Client) InitScan(request *CiScanRequest) (*ScanInfo, error) {
	req, err := client.newRequest(http.MethodPost, "api/ci/scan", request)
	if err != nil {
		return nil, err
	}
	var scanInfo ScanInfo
	_, err = client.do(req, &scanInfo)
	if err != nil {
		return nil, err
	}
	return &scanInfo, nil
}

func (client *Client) UploadSASTFinding(scanId string, findings []finding.SASTFinding) (*UploadSASTFindingResponse, error) {
	body := UploadSASTFindingRequest{
		ScanId:   scanId,
		Findings: findings,
	}
	req, err := client.newRequest(http.MethodPost, "api/ci/sast-finding", &body)
	if err != nil {
		return nil, err
	}
	var response UploadSASTFindingResponse
	_, err = client.do(req, &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

func (client *Client) UpdateScan(scanId string, request UpdateCIScanRequest) error {
	req, err := client.newRequest(http.MethodPut, "api/ci/scan/"+scanId, &request)
	if err != nil {
		return err
	}
	_, err = client.do(req, nil)
	return err
}

func (client *Client) newRequest(method, path string, opt interface{}) (*retryablehttp.Request, error) {
	u := *client.baseURL
	unescaped, err := url.PathUnescape(path)
	if err != nil {
		return nil, err
	}
	// Set the encoded path data
	u.RawPath = client.baseURL.Path + path
	u.Path = client.baseURL.Path + unescaped

	// Create a request specific headers map.
	reqHeaders := make(http.Header)
	reqHeaders.Set("Accept", "application/json")
	reqHeaders.Set("CI-TOKEN", client.apiKey)

	if client.UserAgent != "" {
		reqHeaders.Set("User-Agent", client.UserAgent)
	}

	var body interface{}
	switch {
	case method == http.MethodPatch || method == http.MethodPost || method == http.MethodPut:
		reqHeaders.Set("Content-Type", "application/json")

		if opt != nil {
			body, err = json.Marshal(opt)
			if err != nil {
				return nil, err
			}
		}
	case opt != nil:
		q, err := query.Values(opt)
		if err != nil {
			return nil, err
		}
		u.RawQuery = q.Encode()
	}

	req, err := retryablehttp.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, err
	}
	// Set the request specific headers.
	for k, v := range reqHeaders {
		req.Header[k] = v
	}
	return req, nil
}

func (client *Client) do(req *retryablehttp.Request, v interface{}) (*http.Response, error) {
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		buf := new(strings.Builder)
		io.Copy(buf, resp.Body)
		return nil, errors.New(buf.String())
	}
	defer resp.Body.Close()
	defer io.Copy(io.Discard, resp.Body)
	if v != nil {
		err = json.NewDecoder(resp.Body).Decode(v)
	}
	return resp, err
}

func (client *Client) setBaseURL(urlStr string) error {
	// Make sure the given URL end with a slash
	if !strings.HasSuffix(urlStr, "/") {
		urlStr += "/"
	}
	baseURL, err := url.Parse(urlStr)
	if err != nil {
		return err
	}
	// Update the base URL of the client.
	client.baseURL = baseURL
	return nil
}
