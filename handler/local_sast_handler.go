package handler

import (
	"analyzer/finding"
	"analyzer/git"
	"analyzer/logger"
	"fmt"
)

type LocalSASTHandler struct{}

func NewLocalSASTHandler() *LocalSASTHandler {
	return &LocalSASTHandler{}
}

func (handler *LocalSASTHandler) InitScan(sourceManager git.SourceManager, scanner string) {
}

func (handler *LocalSASTHandler) HandleFindings(sourceManager git.SourceManager, findings []finding.SASTFinding) {
	if sourceManager == nil {
		logger.Warn("There is no source manager (GitLab, GitHub, vv)")
	}
	if len(findings) > 0 {
		logger.Warn(fmt.Sprintf("There are %d new findings", len(findings)))
		PrintSASTFindings(findings)
	} else {
		logger.Info("There are no new findings")
	}
}
