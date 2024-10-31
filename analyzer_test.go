package main

import (
	"analyzer/logger"
	"analyzer/sarif"
	"analyzer/scm"
	"encoding/json"
	"os"
	"testing"
)

func TestScan(t *testing.T) {
	os.Setenv("GITLAB_TOKEN", "change_me")
	os.Setenv("CI_SERVER_URL", "https://gitlab.com")
	os.Setenv("CI_MERGE_REQUEST_IID", "18")
	os.Setenv("CI_PROJECT_ID", "50471840")
	data, _ := os.ReadFile("../testdata/semgrep.sarif")
	var rep sarif.Sarif
	err := json.Unmarshal(data, &rep)
	if err != nil {
		logger.Error(err.Error())
	}
	findings := sarif.ToFindings(&rep)

	RegisterHandler(&DefaultHandler{})
	// register source manager (GitLab, GitHub)
	// gitlab
	gitlab, err := scm.NewGitlab()
	if err != nil {
		logger.Error(err.Error())
	} else {
		RegisterSourceManager(gitlab)
	}
	HandleFindings(findings)
}
