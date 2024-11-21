package analyzer

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/rodaine/table"
	"gitlab.com/code-secure/analyzer/logger"
	"os"
)

type Handler interface {
	InitScan(source SourceManager, scannerName string, scannerType string)
	HandleSAST(sourceManager SourceManager, result SASTResult)
	HandleDependency(sourceManager SourceManager, result SCAResult)
	CompletedScan()
}

func GetHandler() Handler {
	// only init handler if there are no handler
	apiKey := os.Getenv("CODE_SECURE_TOKEN")
	remoteServer := os.Getenv("CODE_SECURE_SERVER")
	if apiKey != "" && remoteServer != "" {
		handler, err := NewRemoteHandler(remoteServer, apiKey)
		if err != nil {
			logger.Error(err.Error())
			os.Exit(1)
		}
		return handler
	}
	return NewLocalHandler()
}

func PrintFindings(findings []Finding) {
	tbl := table.New("ID", "Name", "Severity", "FindingLocation")

	tbl.WithHeaderFormatter(color.New(color.FgGreen, color.Underline).SprintfFunc()).
		WithFirstColumnFormatter(color.New(color.FgYellow).SprintfFunc())
	for index, issue := range findings {
		if issue.Metadata != nil && len(issue.Metadata.FindingFlow) > 0 {
			logger.Info("code flow")
			for _, location := range issue.Metadata.FindingFlow {
				fmt.Println(location.Snippet + " @ " + location.String())
			}
		}
		tbl.AddRow(index+1, issue.Name, issue.Severity, issue.Location.String())
	}
	tbl.Print()
}
