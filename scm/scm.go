package scm

import "analyzer/finding"

type MergeRequest struct {
	SourceBranch      string
	TargetBranch      string
	TargetBranchHash  string
	SourceBranchHash  string
	MergeRequestID    string
	MergeRequestTitle string
}

type SourceManager interface {
	Name() string
	IsActive() bool
	ProjectID() string
	ProjectURL() string
	MergeRequest() (bool, *MergeRequest)
	CommitTag() (bool, string)
	CommitBranch() (bool, string)
	CommitHash() string
	CommitTitle() string
	CommentMergeRequest(findings []finding.Finding, mr *MergeRequest) error
}
