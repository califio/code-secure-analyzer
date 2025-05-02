package git

const (
	GitLab    = "GitLab"
	GitHub    = "GitHub"
	Bitbucket = "Bitbucket"
)

type MRDiscussionOption struct {
	Title     string
	Body      string
	Path      string
	StartLine int
	EndLine   int
}

type GitEnv interface {
	Provider() string
	ProjectID() string
	ProjectName() string
	ProjectURL() string
	CommitTag() string
	CommitBranch() string
	CommitSha() string
	CommitTitle() string
	DefaultBranch() string
	SourceBranch() string
	TargetBranch() string
	TargetBranchSha() string
	MergeRequestID() string
	MergeRequestTitle() string
	JobURL() string
	IsActive() bool
	CreateMRDiscussion(option MRDiscussionOption) error
}
