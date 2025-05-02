package test

import (
	analyzer "github.com/califio/code-secure-analyzer"
	"github.com/califio/code-secure-analyzer/logger"
	"os"
	"testing"
)

type TestScanner struct {
}

func (t TestScanner) Name() string {
	return "test"
}

func (t TestScanner) Type() analyzer.ScannerType {
	return analyzer.ScannerTypeSast
}

func (t TestScanner) Scan(option analyzer.ScanOption) (*analyzer.SastResult, error) {
	logger.Info("Scanning test data")
	return &analyzer.SastResult{}, nil
}

func InitEnv() {
	os.Setenv("CODE_SECURE_URL", "http://localhost:5272")
	os.Setenv("CODE_SECURE_TOKEN", "ab1e097840764f7ba093c43194cbaf8bceea50d3bef144d3994262428d176346")

	os.Setenv("GITLAB_CI", "true")
	os.Setenv("CI_SERVER_URL", "https://gitlab.com")
	os.Setenv("GITLAB_TOKEN", "")
	os.Setenv("CI_PROJECT_ID", "50471840")
	os.Setenv("CI_PROJECT_URL", "https://gitlab.com/0xduo/vulnado")
	os.Setenv("CI_COMMIT_SHA", "72155d553d00f913d1e9b64def483724493da19e")
	os.Setenv("CI_COMMIT_BRANCH", "dev")
	os.Setenv("CI_COMMIT_TITLE", "Commit Test")
}
func TestSastAnalyzer(t *testing.T) {
	InitEnv()
	anlyz := analyzer.NewSastAnalyzer(analyzer.SastAnalyzerOption{
		ProjectPath: "/tmp/foo",
		Scanner:     &TestScanner{},
	})
	anlyz.Run()
}
