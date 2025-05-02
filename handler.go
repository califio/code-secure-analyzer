package analyzer

import (
	"fmt"
	"github.com/califio/code-secure-analyzer/git"
	"github.com/califio/code-secure-analyzer/logger"
	"github.com/jedib0t/go-pretty/v6/table"
	"os"
)

type HandleSastFindingPros struct {
	Result        SastResult
	Strategy      ScanStrategy
	ChangedFiles  []ChangedFile
	SourceManager git.GitEnv
}

type Handler interface {
	OnStart(source git.GitEnv, scannerName string, scannerType ScannerType) (*CiScanInfo, error)
	OnCompleted()
	OnError(err error)
	HandleSastFindings(input HandleSastFindingPros)
	HandleSCA(sourceManager git.GitEnv, result ScaResult)
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

func printFindings(findings []SastFinding) {
	tbl := table.NewWriter()
	tbl.SetOutputMirror(os.Stdout)
	tbl.SetStyle(table.StyleLight)
	tbl.Style().Options.SeparateRows = true
	tbl.AppendHeader(table.Row{"ID", "Name", "Severity", "Location"})
	for index, issue := range findings {
		tbl.AppendRow(table.Row{index + 1, issue.Name, issue.Severity, issue.Location.String()})
	}
	tbl.Render()
}

// default handler

// local handler

type LocalHandler struct{}

func NewLocalHandler() *LocalHandler {
	return &LocalHandler{}
}

func (handler *LocalHandler) OnStart(sourceManager git.GitEnv, scannerName string, scannerType ScannerType) (*CiScanInfo, error) {
	return &CiScanInfo{}, nil
}
func (handler *LocalHandler) OnCompleted() {
	logger.Info("scan completed")
}
func (handler *LocalHandler) OnError(err error) {
	logger.Error(err.Error())
}

func (handler *LocalHandler) HandleSastFindings(input HandleSastFindingPros) {
	if input.SourceManager == nil {
		logger.Warn("there is no source manager (GitLab, GitHub, vv)")
	}
	if len(input.Result.Findings) > 0 {
		logger.Warn(fmt.Sprintf("there are %d new findings", len(input.Result.Findings)))
		printFindings(input.Result.Findings)
	} else {
		logger.Info("there are no new findings")
	}
}

func (handler *LocalHandler) HandleSCA(sourceManager git.GitEnv, result ScaResult) {
	//todo: write something here
}
