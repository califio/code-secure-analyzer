package finding

import "fmt"

type Location struct {
	Path        string
	Snippet     string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
}

func (l *Location) String() string {
	return fmt.Sprintf("%s:%d:%d", l.Path, l.StartLine, l.EndLine)
}

type Finding struct {
	RuleID         string
	Identity       string
	Name           string
	Description    string
	Recommendation string
	Severity       string
	Location       *Location
	CodeFlow       []Location
}
