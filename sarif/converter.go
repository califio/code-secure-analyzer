package sarif

import (
	"analyzer/finding"
	"analyzer/logger"
	"fmt"
)

func ToFindings(report *Sarif) []finding.Finding {
	var findings []finding.Finding
	mExists := make(map[string]bool)
	for _, run := range report.Runs {
		issues, err := transformRun(run)
		if err != nil {
			logger.Error(err.Error())
		}
		for _, issue := range issues {
			if _, exist := mExists[issue.Identity]; exist == false {
				findings = append(findings, issue)
				mExists[issue.Identity] = true
			}
		}
	}
	return findings
}

func transformRun(r Run) ([]finding.Finding, error) {
	mRules := make(map[string]Rule)
	for _, rule := range r.Tool.Driver.Rules {
		mRules[rule.ID] = rule
	}

	var findings []finding.Finding
	for _, result := range r.Results {
		ruleId := result.RuleID
		rule := mRules[ruleId]
		description := result.Message.Text
		if len(result.Locations) > 0 {
			physicalLocation := result.Locations[0].PhysicalLocation
			location := finding.Location{
				Path:        physicalLocation.ArtifactLocation.Uri,
				Snippet:     physicalLocation.Region.Snippet.Text,
				StartLine:   physicalLocation.Region.StartLine,
				EndLine:     physicalLocation.Region.EndLine,
				StartColumn: physicalLocation.Region.StartColumn,
				EndColumn:   physicalLocation.Region.EndColumn,
			}
			findings = append(findings, finding.Finding{
				RuleID:         result.RuleID,
				Identity:       result.Fingerprints.Id,
				Name:           fmt.Sprintf("Semgrep Finding: %s", result.RuleID),
				Description:    description,
				Recommendation: "",
				Severity:       rule.Severity(),
				Location:       &location,
				CodeFlow:       result.GetCodeFlow(),
			})
		}
	}
	return findings, nil
}
