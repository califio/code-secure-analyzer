package analyzer

import (
	"fmt"
)

type FindingLocation struct {
	Path        string `json:"path,omitempty"`
	Snippet     string `json:"snippet,omitempty"`
	StartLine   int    `json:"startLine,omitempty"`
	EndLine     int    `json:"endLine,omitempty"`
	StartColumn int    `json:"startColumn,omitempty"`
	EndColumn   int    `json:"endColumn,omitempty"`
}

func (location *FindingLocation) String() string {
	result := location.Path
	if location.StartLine > 0 {
		result += fmt.Sprintf(":%d", location.StartLine)
		if location.EndLine > 0 {
			result += fmt.Sprintf(":%d", location.EndLine)
		}
	}
	return result
}

type SastFinding struct {
	ID             string           `json:"id,omitempty"`
	RuleID         string           `json:"ruleId,omitempty" json:"ruleID,omitempty"`
	Identity       string           `json:"identity,omitempty" json:"identity,omitempty"`
	Name           string           `json:"name,omitempty" json:"name,omitempty"`
	Description    string           `json:"description,omitempty" json:"description,omitempty"`
	Category       string           `json:"category,omitempty" json:"category,omitempty"`
	Recommendation string           `json:"recommendation,omitempty" json:"recommendation,omitempty"`
	Severity       Severity         `json:"severity,omitempty" json:"severity,omitempty"`
	Location       *FindingLocation `json:"location,omitempty" json:"location,omitempty"`
	Metadata       *FindingMetadata `json:"metadata,omitempty" json:"metadata,omitempty"`
}

type FindingMetadata struct {
	FindingFlow []FindingLocation `json:"findingFlow,omitempty"`
	Cwes        []string          `json:"cwes,omitempty"`
	References  []string          `json:"references,omitempty"`
	Cvss        *string           `json:"cvss,omitempty"`
	CvssScore   *string           `json:"cvssScore,omitempty"`
}
