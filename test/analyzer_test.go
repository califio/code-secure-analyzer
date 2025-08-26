package test

import (
	"fmt"
	analyzer "github.com/califio/code-secure-analyzer"
	"github.com/califio/code-secure-analyzer/logger"
	"github.com/joho/godotenv"
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

func TestSastAnalyzer(t *testing.T) {
	_ = godotenv.Load()
	fmt.Println("Project path: " + os.Getenv("PROJECT_PATH"))
	anlyz := analyzer.NewSastAnalyzer(analyzer.SastAnalyzerOption{
		ProjectPath: os.Getenv("PROJECT_PATH"),
		Scanner:     &TestScanner{},
	})
	anlyz.Run()
}
