package analyzer

import (
	"context"
)

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
	ProjectName() string
	ProjectGroup() string
	MergeRequest() *MergeRequest
	CommitTag() string
	CommitBranch() string
	CommitHash() string
	CommitTitle() string
	DefaultBranch() string
	JobURL() string
	CommentFindingOnMergeRequest(context context.Context, findings []Finding, mr *MergeRequest) error
}
