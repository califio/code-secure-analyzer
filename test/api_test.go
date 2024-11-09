package test

import (
	"gitlab.com/code-secure/analyzer/api"
	"gitlab.com/code-secure/analyzer/finding"
	"gitlab.com/code-secure/analyzer/logger"
	"testing"
)

func TestScanSAST(t *testing.T) {
	client, err := api.NewClient("http://localhost:5272", "4084269e05de4cddacb3ef4f9333848e51b7d36b610441919080b0dfde6888f8")
	if err != nil {
		logger.Fatal(err.Error())
		t.Fail()
	}
	scan, err := client.InitScan(&api.CiScanRequest{
		Source:         "GitLab",
		RepoId:         "50471840",
		RepoUrl:        "https://gitlab.com/0xduo/vulnado",
		RepoName:       "0xduo/vulnado",
		GitAction:      api.GitCommitBranch,
		ScanTitle:      "Test Commit",
		CommitBranch:   "main",
		CommitHash:     "891832b2fdecb72c444af1a6676eba6eb40435ab",
		TargetBranch:   "",
		MergeRequestId: "",
		Scanner:        "semgrep",
		Type:           api.ScanSAST,
		JobUrl:         "https://gitlab.com/0xduo/vulnado/-/jobs/8241092355",
		IsDefault:      true,
	})
	if err != nil {
		logger.Error(err.Error())
		t.Fail()
	}
	if scan == nil || scan.ScanId == "" {
		t.Fail()
	}
	findings := []finding.SASTFinding{
		finding.SASTFinding{
			RuleID:         "rule-test-02",
			Identity:       "rule-test-02",
			Name:           "Finding Test 02",
			Description:    "Finding Description 02",
			Recommendation: "",
			Severity:       api.SeverityCritical,
			Location: &finding.Location{
				Path:        "src/test.java",
				Snippet:     "input",
				StartLine:   4,
				EndLine:     4,
				StartColumn: 0,
				EndColumn:   0,
			},
			FindingFlow: []finding.Location{
				finding.Location{
					Path:        "src/test.java",
					Snippet:     "sink",
					StartLine:   4,
					EndLine:     4,
					StartColumn: 0,
					EndColumn:   0,
				},
				finding.Location{
					Path:        "src/test.java",
					Snippet:     "sink",
					StartLine:   8,
					EndLine:     8,
					StartColumn: 0,
					EndColumn:   0,
				},
			},
		},
	}
	_, err = client.UploadSASTFinding(scan.ScanId, findings)
	if err != nil {
		logger.Error(err.Error())
		t.Fail()
	}
	err = client.UpdateScan(scan.ScanId, api.UpdateCIScanRequest{
		Status:      api.Ptr(api.StatusCompleted),
		Description: nil,
	})
	if err != nil {
		logger.Error(err.Error())
		t.Fail()
	}
}
