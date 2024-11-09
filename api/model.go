package api

import "gitlab.com/code-secure/analyzer/finding"

type CiScanRequest struct {
	Source         string `json:"source,omitempty"`
	RepoId         string `json:"repoId,omitempty"`
	RepoUrl        string `json:"repoUrl,omitempty"`
	RepoName       string `json:"repoName,omitempty"`
	GitAction      string `json:"gitAction,omitempty"`
	ScanTitle      string `json:"scanTitle,omitempty"`
	CommitHash     string `json:"commitHash,omitempty"`
	CommitBranch   string `json:"commitBranch,omitempty"`
	TargetBranch   string `json:"targetBranch,omitempty"`
	MergeRequestId string `json:"mergeRequestId,omitempty"`
	Scanner        string `json:"scanner,omitempty"`
	Type           string `json:"type,omitempty"`
	JobUrl         string `json:"jobUrl,omitempty"`
	IsDefault      bool   `json:"isDefault,omitempty"`
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
