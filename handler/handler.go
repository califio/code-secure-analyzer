package handler

import (
	"analyzer/api"
	"analyzer/finding"
	"analyzer/git"
	"analyzer/logger"
	"fmt"
	"github.com/fatih/color"
	"github.com/rodaine/table"
	"os"
)

type FindingResponse[T any] struct {
	NewFindings       []T
	FixedFindings     []T
	OpenFindings      []T
	ConfirmedFindings []T
}

type Handler[T any] interface {
	HandleFindings(sourceManager git.SourceManager, findings []T)
	InitScan(sourceManager git.SourceManager, scanner string)
}

func GetSASTHandler() Handler[finding.SASTFinding] {
	// only init handler if there are no handler
	apiKey := os.Getenv("CODE_SECURE_TOKEN")
	remoteServer := os.Getenv("CODE_SECURE_SERVER")
	if apiKey != "" && remoteServer != "" {
		apiClient, err := api.NewClient(remoteServer, apiKey)
		if err != nil {
			logger.Error(err.Error())
		}
		if err == nil && apiClient.TestConnection() {
			return NewRemoteSASTHandler(apiClient)
		}
	}
	return NewLocalSASTHandler()
}

func PrintSASTFindings(findings []finding.SASTFinding) {
	tbl := table.New("ID", "Name", "Severity", "FindingLocation")

	tbl.WithHeaderFormatter(color.New(color.FgGreen, color.Underline).SprintfFunc()).
		WithFirstColumnFormatter(color.New(color.FgYellow).SprintfFunc())
	for index, issue := range findings {
		if len(issue.FindingFlow) > 0 {
			logger.Info("code flow")
			for _, location := range issue.FindingFlow {
				fmt.Println(location.Snippet + " @ " + location.String())
			}
		}
		tbl.AddRow(index+1, issue.Name, issue.Severity, issue.Location.String())
	}
	tbl.Print()
}
