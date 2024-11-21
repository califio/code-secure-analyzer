package analyzer

// git action
const (
	GitCommitBranch = "CommitBranch"
	GitMergeRequest = "MergeRequest"
	GitCommitTag    = "CommitTag"
)

// scanner
const (
	Sast            = "Sast"
	Dast            = "Dast"
	Iast            = "Iast"
	Dependency      = "Dependency"
	Container       = "Container"
	SecretDetection = "Secret"
)

// severity
const (
	SeverityCritical = "Critical"
	SeverityHigh     = "High"
	SeverityMedium   = "Medium"
	SeverityLow      = "Low"
	SeverityInfo     = "Info"
)

// scan status
const (
	StatusCompleted = "Completed"
	StatusRunning   = "Running"
	StatusError     = "Error"
)
