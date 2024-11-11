package api

import "gitlab.com/code-secure/analyzer/finding"

type CiScanRequest struct {
	Source         string `json:"source"`
	RepoId         string `json:"repoId"`
	RepoUrl        string `json:"repoUrl"`
	RepoName       string `json:"repoName"`
	GitAction      string `json:"gitAction"`
	ScanTitle      string `json:"scanTitle"`
	CommitHash     string `json:"commitHash"`
	CommitBranch   string `json:"commitBranch"`
	TargetBranch   string `json:"targetBranch"`
	MergeRequestId string `json:"mergeRequestId"`
	Scanner        string `json:"scanner"`
	Type           string `json:"type"`
	JobUrl         string `json:"jobUrl"`
	IsDefault      bool   `json:"isDefault"`
}

type ScanInfo struct {
	ScanId string `json:"scanId"`
}

type UploadSASTFindingResponse struct {
	NewFindings       []finding.SASTFinding
	ConfirmedFindings []finding.SASTFinding
	OpenFindings      []finding.SASTFinding
	FixedFindings     []finding.SASTFinding
}

type UploadSASTFindingRequest struct {
	ScanId   string                `json:"scanId,omitempty"`
	Findings []finding.SASTFinding `json:"findings,omitempty"`
}

type UpdateCIScanRequest struct {
	Status      *string `json:"status,omitempty"`
	Description *string `json:"description,omitempty"`
}
