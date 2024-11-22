package analyzer

type GitAction string

const (
	GitCommitBranch GitAction = "CommitBranch"
	GitMergeRequest GitAction = "MergeRequest"
	GitCommitTag    GitAction = "CommitTag"
)

type Severity string

const (
	SeverityCritical Severity = "Critical"
	SeverityHigh     Severity = "High"
	SeverityMedium   Severity = "Medium"
	SeverityLow      Severity = "Low"
	SeverityInfo     Severity = "Info"
)

type ScanStatus string

const (
	StatusCompleted ScanStatus = "Completed"
	StatusRunning   ScanStatus = "Running"
	StatusError     ScanStatus = "Error"
)
