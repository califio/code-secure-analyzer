package analyzer

const (
	AllFiles        ScanStrategy = "AllFiles"
	ChangedFileOnly ScanStrategy = "ChangedFileOnly"
)

const (
	StatusCompleted ScanStatus = "Completed"
	StatusRunning   ScanStatus = "Running"
	StatusError     ScanStatus = "Error"
)

type ScanStrategy string

func (a ScanStrategy) String() string {
	if a == ChangedFileOnly {
		return "Changed File Only"
	}
	if a == AllFiles {
		return "All Files"
	}
	return "Unknown"
}

type ScanStatus string

type ScanOption struct {
	ChangedFiles  []ChangedFile
	ScanType      ScanStrategy
	LastCommitSha string
}
