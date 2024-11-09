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

type SASTFinding struct {
	RuleID         string     `json:"ruleId,omitempty"`
	Identity       string     `json:"identity,omitempty"`
	Name           string     `json:"name,omitempty"`
	Description    string     `json:"description,omitempty"`
	Recommendation string     `json:"recommendation,omitempty"`
	Severity       string     `json:"severity,omitempty"`
	Location       *Location  `json:"location,omitempty"`
	FindingFlow    []Location `json:"findingFlow,omitempty"`
}
