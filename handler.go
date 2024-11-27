package analyzer

import (
	"github.com/fatih/color"
	"github.com/rodaine/table"
	"gitlab.com/code-secure/analyzer/logger"
	"os"
)

type Handler interface {
	InitScan(source SourceManager, scannerName string, scannerType ScannerType)
	HandleFindings(sourceManager SourceManager, result FindingResult)
	HandleSCA(sourceManager SourceManager, result SCAResult)
	CompletedScan()
}

func GetHandler() Handler {
	// only init handler if there are no handler
	apiKey := os.Getenv("CODE_SECURE_TOKEN")
	remoteServer := os.Getenv("CODE_SECURE_URL")
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
	tbl := table.New("ID", "Name", "Severity", "Location")

	tbl.WithHeaderFormatter(color.New(color.FgGreen, color.Underline).SprintfFunc()).
		WithFirstColumnFormatter(color.New(color.FgYellow).SprintfFunc())
	for index, issue := range findings {
		tbl.AddRow(index+1, issue.Name, issue.Severity, issue.Location.String())
	}
	tbl.Print()
}
