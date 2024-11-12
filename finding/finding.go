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
	ID             string     `json:"id,omitempty"`
	RuleID         string     `json:"ruleId,omitempty" json:"ruleID,omitempty"`
	Identity       string     `json:"identity,omitempty" json:"identity,omitempty"`
	Name           string     `json:"name,omitempty" json:"name,omitempty"`
	Description    string     `json:"description,omitempty" json:"description,omitempty"`
	Category       string     `json:"category,omitempty" json:"category,omitempty"`
	Recommendation string     `json:"recommendation,omitempty" json:"recommendation,omitempty"`
	Severity       string     `json:"severity,omitempty" json:"severity,omitempty"`
	Location       *Location  `json:"location,omitempty" json:"location,omitempty"`
	FindingFlow    []Location `json:"findingFlow,omitempty" json:"findingFlow,omitempty"`
}
