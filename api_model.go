package analyzer

type UploadFindingRequest struct {
	ScanId   string    `json:"scanId,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
}

type UploadFindingResponse struct {
	NewFindings       []Finding `json:"newFindings,omitempty"`
	ConfirmedFindings []Finding `json:"confirmedFindings,omitempty"`
	OpenFindings      []Finding `json:"openFindings,omitempty"`
	FixedFindings     []Finding `json:"fixedFindings,omitempty"`
	IsBlock           bool      `json:"isBlock,omitempty"`
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
	IsDefault      *bool  `json:"isDefault"`
}

type UpdateCIScanRequest struct {
	Status      *string `json:"status,omitempty"`
	Description *string `json:"description,omitempty"`
}

type ScanInfo struct {
	ScanId string `json:"scanId"`
}
