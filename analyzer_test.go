package main

import (
	"analyzer/finding"
	"analyzer/git"
	"analyzer/handler"
	"analyzer/logger"
	"analyzer/sarif"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestScanGitlabRepo(t *testing.T) {
	os.Setenv("GITLAB_TOKEN", "change_me")
	os.Setenv("CI_SERVER_URL", "https://gitlab.com")
	//os.Setenv("CI_MERGE_REQUEST_IID", "18")
	os.Setenv("CI_PROJECT_ID", "50471840")
	os.Setenv("CI_PROJECT_URL", "https://gitlab.com/0xduo/vulnado")
	os.Setenv("CI_PROJECT_URL", "https://gitlab.com/0xduo/vulnado")
	os.Setenv("CI_PROJECT_NAME", "vulnado")
	os.Setenv("CI_PROJECT_NAMESPACE", "0xduo")
	os.Setenv("CI_COMMIT_TITLE", "Commit Test")
	os.Setenv("CI_COMMIT_BRANCH", "main")
	os.Setenv("CI_DEFAULT_BRANCH", "main")
	os.Setenv("CI_JOB_URL", "https://gitlab.com/0xduo/vulnado/-/jobs/8241092355")
	os.Setenv("CI_COMMIT_SHA", "891832b2fdecb72c444af1a6676eba6eb40435ab")
	os.Setenv("CODE_SECURE_TOKEN", "4084269e05de4cddacb3ef4f9333848e51b7d36b610441919080b0dfde6888f8")
	os.Setenv("CODE_SECURE_SERVER", "http://localhost:5272")
	data, err := os.ReadFile("testdata/semgrep.sarif")
	if err != nil {
		logger.Error(err.Error())
	}
	var rep sarif.Sarif
	err = json.Unmarshal(data, &rep)
	if err != nil {
		logger.Fatal(err.Error())
	}
	findings := sarif.ToFindings(&rep)
	analyzer := NewAnalyzer[finding.SASTFinding]()
	handler := handler.GetSASTHandler()
	analyzer.RegisterHandler(handler)
	// source manager
	gitlab, err := git.NewGitlab()
	analyzer.RegisterSourceManager(gitlab)
	analyzer.handler.InitScan(gitlab, "semgrep")
	analyzer.HandleFindings(findings)
}

func TestParseMessage(t *testing.T) {
	message := "Source: 'input' @ 'src/main/java/com/scalesec/vulnado/LoginController.java:19'"
	arr := strings.Split(message, "@")
	if len(arr) != 2 {
		t.Fail()
	}
	path := strings.Trim(arr[1], " '")
	arr = strings.Split(path, ":")
	if len(arr) != 2 {
		t.Fail()
	}
	logger.Info(arr[0])
}
