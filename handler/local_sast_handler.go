package handler

import (
	"fmt"
	"gitlab.com/code-secure/analyzer/finding"
	"gitlab.com/code-secure/analyzer/git"
	"gitlab.com/code-secure/analyzer/logger"
)

type LocalSASTHandler struct{}

func NewLocalSASTHandler() *LocalSASTHandler {
	return &LocalSASTHandler{}
}

func (handler *LocalSASTHandler) InitScan(sourceManager git.SourceManager, scanner string) {
}

func (handler *LocalSASTHandler) HandleFindings(sourceManager git.SourceManager, findings []finding.SASTFinding) {
	if sourceManager == nil {
		logger.Warn("there is no source manager (GitLab, GitHub, vv)")
	}
	if len(findings) > 0 {
		logger.Warn(fmt.Sprintf("there are %d new findings", len(findings)))
		PrintSASTFindings(findings)
	} else {
		logger.Info("there are no new findings")
	}
}

func (handler *LocalSASTHandler) CompletedScan() {
	logger.Info("scan completed")
}
