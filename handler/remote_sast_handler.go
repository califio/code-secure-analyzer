package handler

import (
	"context"
	"errors"
	"fmt"
	"gitlab.com/code-secure/analyzer/api"
	"gitlab.com/code-secure/analyzer/finding"
	"gitlab.com/code-secure/analyzer/git"
	"gitlab.com/code-secure/analyzer/logger"
	"os"
)

type RemoteSASTHandler struct {
	server  string
	token   string
	scanId  string
	isBlock bool
	client  *api.Client
}

func NewRemoteSASTHandler(codeSecureServer, codeSecureToken string) (*RemoteSASTHandler, error) {
	apiClient, err := api.NewClient(codeSecureServer, codeSecureToken)
	if err != nil {
		return nil, err
	}
	if apiClient.TestConnection() {
		return &RemoteSASTHandler{server: codeSecureServer, token: codeSecureToken, client: apiClient, isBlock: false}, nil
	}
	return nil, errors.New("failed to connect to remote server")
}

func (handler *RemoteSASTHandler) HandleFindings(sourceManager git.SourceManager, findings []finding.SASTFinding) {
	response, err := handler.client.UploadSASTFinding(handler.scanId, findings)
	if err != nil {
		logger.Error(err.Error())
		return
	}
	if sourceManager == nil {
		logger.Warn("there is no source manager (GitLab, GitHub, vv)")
	}
	if len(response.NewFindings) > 0 {
		logger.Warn(fmt.Sprintf("There are %d new findings", len(response.NewFindings)))
		PrintSASTFindings(response.NewFindings)
	}

	if len(response.FixedFindings) > 0 {
		logger.Info(fmt.Sprintf("There are %d findings that have been fixed", len(response.FixedFindings)))
		PrintSASTFindings(response.FixedFindings)
	}

	if len(response.ConfirmedFindings) > 0 {
		logger.Info(fmt.Sprintf("There are still %d findings not yet fixed", len(response.ConfirmedFindings)))
		PrintSASTFindings(response.ConfirmedFindings)
	}

	if len(response.OpenFindings) > 0 {
		logger.Info(fmt.Sprintf("There are %d findings need to verify", len(response.OpenFindings)))
		PrintSASTFindings(response.OpenFindings)
	}

	if sourceManager != nil {
		// comment new findings on merge request
		mergeRequest := sourceManager.MergeRequest()
		if mergeRequest != nil {
			if len(response.NewFindings) > 0 {
				ctx := context.WithValue(context.Background(), "server", handler.server)
				err := sourceManager.CommentSASTFindingOnMergeRequest(ctx, findings, mergeRequest)
				if err != nil {
					logger.Error("Comment on merge request error")
					logger.Error(err.Error())
				}
			}
		}
	}
	handler.isBlock = response.IsBlock
}

func (handler *RemoteSASTHandler) InitScan(sourceManager git.SourceManager, scanner string) {
	gitAction := api.GitCommitBranch
	scanTitle := sourceManager.CommitTitle()
	commitBranch := sourceManager.CommitBranch()
	targetBranch := ""
	mergeRequestId := ""
	if sourceManager.CommitBranch() != "" {
		gitAction = api.GitCommitBranch
	}
	if sourceManager.CommitTag() != "" {
		gitAction = api.GitCommitTag
	}
	mergeRequest := sourceManager.MergeRequest()
	if mergeRequest != nil {
		gitAction = api.GitMergeRequest
		scanTitle = mergeRequest.MergeRequestTitle
		commitBranch = mergeRequest.SourceBranch
		targetBranch = mergeRequest.TargetBranch
		mergeRequestId = mergeRequest.MergeRequestID
	}
	repoName := sourceManager.ProjectGroup() + "/" + sourceManager.ProjectName()
	isDefault := commitBranch == sourceManager.DefaultBranch()
	body := api.CiScanRequest{
		Source:         sourceManager.Name(),
		RepoId:         sourceManager.ProjectID(),
		RepoUrl:        sourceManager.ProjectURL(),
		RepoName:       repoName,
		GitAction:      gitAction,
		ScanTitle:      scanTitle,
		CommitBranch:   commitBranch,
		CommitHash:     sourceManager.CommitHash(),
		TargetBranch:   targetBranch,
		MergeRequestId: mergeRequestId,
		Scanner:        scanner,
		Type:           api.ScanSAST,
		JobUrl:         sourceManager.JobURL(),
		IsDefault:      api.Ptr(isDefault),
	}
	scanInfo, err := handler.client.InitScan(&body)
	if scanInfo != nil {
		logger.Info("Scan initialized: " + scanInfo.ScanId)
		handler.scanId = scanInfo.ScanId
	}
	if err != nil {
		logger.Error(err.Error())
	}
}

func (handler *RemoteSASTHandler) CompletedScan() {
	err := handler.client.UpdateScan(handler.scanId, api.UpdateCIScanRequest{
		Status:      api.Ptr(api.StatusCompleted),
		Description: nil,
	})
	if err != nil {
		logger.Error(err.Error())
	}
	if handler.isBlock {
		logger.Info(fmt.Sprintf("block due security config"))
		os.Exit(1)
	}
}
