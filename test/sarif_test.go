package test

import (
	"analyzer/logger"
	"analyzer/sarif"
	"encoding/json"
	"os"
	"testing"
)

func TestGetRules(t *testing.T) {
	data, _ := os.ReadFile("../testdata/semgrep.sarif")
	var rep sarif.Sarif
	err := json.Unmarshal(data, &rep)
	if err != nil {
		logger.Error(err.Error())
	}
	findings := sarif.ToFindings(&rep)
	for _, finding := range findings {
		println(finding.RuleID)
		println(finding.Description)
		println(finding.Severity)
		println(finding.Location.String())
		if finding.CodeFlow != nil {
			for _, location := range finding.CodeFlow {
				println(location.String())
			}
		}
		println("-----------")
	}
}
