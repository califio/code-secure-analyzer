package analyzer

import (
	"github.com/califio/code-secure-analyzer/logger"
	"github.com/go-resty/resty/v2"
	"strings"
)

type UploadFindingRequest struct {
	ScanId       string        `json:"scanId,omitempty"`
	Findings     []SastFinding `json:"findings,omitempty"`
	Strategy     ScanStrategy  `json:"strategy,omitempty"`
	ChangedFiles []ChangedFile `json:"changedFiles,omitempty"`
}

type UploadFindingResponse struct {
	FindingUrl        string        `json:"findingUrl,omitempty"`
	NewFindings       []SastFinding `json:"newFindings,omitempty"`
	ConfirmedFindings []SastFinding `json:"confirmedFindings,omitempty"`
	OpenFindings      []SastFinding `json:"openFindings,omitempty"`
	FixedFindings     []SastFinding `json:"fixedFindings,omitempty"`
	IsBlock           bool          `json:"isBlock,omitempty"`
}

type UploadDependencyRequest struct {
	ScanId              string              `json:"scanId,omitempty"`
	Packages            []Package           `json:"packages,omitempty"`
	PackageDependencies []PackageDependency `json:"packageDependencies,omitempty"`
	Vulnerabilities     []Vulnerability     `json:"vulnerabilities,omitempty"`
}

type UploadDependencyResponse struct {
	Packages []PackageInfo `json:"packages,omitempty"`
	IsBlock  bool          `json:"isBlock,omitempty"`
}

type CiScanRequest struct {
	Source         string      `json:"source"`
	RepoId         string      `json:"repoId"`
	RepoUrl        string      `json:"repoUrl"`
	RepoName       string      `json:"repoName"`
	GitAction      GitAction   `json:"gitAction"`
	ScanTitle      string      `json:"scanTitle"`
	CommitHash     string      `json:"commitHash"`
	CommitBranch   string      `json:"commitBranch"`
	TargetBranch   string      `json:"targetBranch"`
	MergeRequestId string      `json:"mergeRequestId"`
	Scanner        string      `json:"scanner"`
	Type           ScannerType `json:"type"`
	JobUrl         string      `json:"jobUrl"`
	IsDefault      *bool       `json:"isDefault"`
}

type UpdateCIScanRequest struct {
	Status      *ScanStatus `json:"status,omitempty"`
	Description *string     `json:"description,omitempty"`
}

type CiScanInfo struct {
	ScanId        string `json:"scanId"`
	ScanUrl       string `json:"scanUrl"`
	LastCommitSha string `json:"lastCommitSha"`
}

type Client struct {
	baseURL    string
	apiKey     string
	httpClient *resty.Client
	UserAgent  string
}

func NewClient(baseUrl string, apiKey string) *Client {
	client := &Client{
		apiKey:     apiKey,
		httpClient: resty.New(),
		baseURL:    strings.TrimSuffix(baseUrl, "/"),
	}
	return client
}

func (client *Client) TestConnection() bool {
	res, err := client.Request().Get(client.baseURL + "/api/ci/ping")
	if err != nil {
		logger.Error(err.Error())
		return false
	}
	if res.StatusCode() == 403 || res.StatusCode() == 401 {
		logger.Error("Token is invalid")
		return false
	}
	return res.StatusCode() == 200
}

func (client *Client) InitScan(request CiScanRequest) (*CiScanInfo, error) {
	var scanInfo CiScanInfo
	_, err := client.Request().
		SetBody(request).
		SetResult(&scanInfo).
		Post(client.baseURL + "/api/ci/scan")
	if err != nil {
		return nil, err
	}
	return &scanInfo, nil
}

func (client *Client) UploadFinding(request UploadFindingRequest) (*UploadFindingResponse, error) {
	var response UploadFindingResponse
	_, err := client.Request().
		SetBody(request).
		SetResult(&response).
		Post(client.baseURL + "/api/ci/finding")
	if err != nil {
		return nil, err
	}
	return &response, nil
}

func (client *Client) UploadDependency(request UploadDependencyRequest) (*UploadDependencyResponse, error) {
	var response UploadDependencyResponse
	_, err := client.Request().
		SetBody(request).
		SetResult(&response).
		Post(client.baseURL + "/api/ci/dependency")
	if err != nil {
		return nil, err
	}
	return &response, nil
}

func (client *Client) UpdateScan(scanId string, request UpdateCIScanRequest) error {
	_, err := client.Request().
		SetBody(request).
		Put(client.baseURL + "/api/ci/scan/" + scanId)
	return err
}

func (client *Client) Request() *resty.Request {
	return client.httpClient.R().SetHeader("CI-TOKEN", client.apiKey)
}
