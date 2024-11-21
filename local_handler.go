package analyzer

import (
	"fmt"
	"gitlab.com/code-secure/analyzer/logger"
)

type LocalHandler struct{}

func NewLocalHandler() *LocalHandler {
	return &LocalHandler{}
}

func (handler *LocalHandler) InitScan(sourceManager SourceManager, scannerName string, scannerType string) {
}

func (handler *LocalHandler) HandleSAST(sourceManager SourceManager, result SASTResult) {
	if sourceManager == nil {
		logger.Warn("there is no source manager (GitLab, GitHub, vv)")
	}
	if len(result.Findings) > 0 {
		logger.Warn(fmt.Sprintf("there are %d new findings", len(result.Findings)))
		PrintFindings(result.Findings)
	} else {
		logger.Info("there are no new findings")
	}
}

func (handler *LocalHandler) HandleDependency(sourceManager SourceManager, result SCAResult) {
	//todo: write something here
}

func (handler *LocalHandler) CompletedScan() {
	logger.Info("scan completed")
}