package analyzer

import (
	"context"
	"errors"
	"fmt"
	"gitlab.com/code-secure/analyzer/logger"
	"os"
)

type RemoteHandler struct {
	server  string
	token   string
	scanId  string
	isBlock bool
	client  *Client
}

func NewRemoteHandler(codeSecureServer, codeSecureToken string) (*RemoteHandler, error) {
	apiClient, err := NewClient(codeSecureServer, codeSecureToken)
	if err != nil {
		return nil, err
	}
	if apiClient.TestConnection() {
		return &RemoteHandler{server: codeSecureServer, token: codeSecureToken, client: apiClient, isBlock: false}, nil
	}
	return nil, errors.New("failed to connect to remote server")
}

func (handler *RemoteHandler) HandleSCA(sourceManager SourceManager, result SCAResult) {
	response, err := handler.client.UploadDependency(UploadDependencyRequest{
		ScanId:              handler.scanId,
		Packages:            result.Packages,
		PackageDependencies: result.PackageDependencies,
		Vulnerabilities:     result.Vulnerabilities,
	})
	if err != nil {
		logger.Error(err.Error())
		return
	}
	handler.isBlock = response.IsBlock
}

func (handler *RemoteHandler) HandleFindings(sourceManager SourceManager, result FindingResult) {
	response, err := handler.client.UploadFinding(UploadFindingRequest{
		ScanId:   handler.scanId,
		Findings: result.Findings,
	})
	if err != nil {
		logger.Error(err.Error())
		return
	}
	if sourceManager == nil {
		logger.Warn("there is no source manager (GitLab, GitHub, vv)")
	}
	if len(response.NewFindings) > 0 {
		logger.Warn(fmt.Sprintf("There are %d new findings", len(response.NewFindings)))
		PrintFindings(response.NewFindings)
	}

	if len(response.FixedFindings) > 0 {
		logger.Info(fmt.Sprintf("There are %d findings that have been fixed", len(response.FixedFindings)))
		PrintFindings(response.FixedFindings)
	}

	if len(response.ConfirmedFindings) > 0 {
		logger.Info(fmt.Sprintf("There are still %d findings not yet fixed", len(response.ConfirmedFindings)))
		PrintFindings(response.ConfirmedFindings)
	}

	if len(response.OpenFindings) > 0 {
		logger.Info(fmt.Sprintf("There are %d findings need to verify", len(response.OpenFindings)))
		PrintFindings(response.OpenFindings)
	}

	if sourceManager != nil {
		// comment new findings on merge request
		mergeRequest := sourceManager.MergeRequest()
		if mergeRequest != nil {
			if len(response.NewFindings) > 0 {
				ctx := context.WithValue(context.Background(), "server", handler.server)
				err := sourceManager.CommentFindingOnMergeRequest(ctx, response.NewFindings, mergeRequest)
				if err != nil {
					logger.Error("Comment on merge request error")
					logger.Error(err.Error())
				}
			}
		}
	}
	handler.isBlock = response.IsBlock
}

func (handler *RemoteHandler) InitScan(sourceManager SourceManager, scannerName string, scannerType ScannerType) {
	gitAction := GitCommitBranch
	scanTitle := sourceManager.CommitTitle()
	commitBranch := sourceManager.CommitBranch()
	targetBranch := ""
	mergeRequestId := ""
	if sourceManager.CommitBranch() != "" {
		gitAction = GitCommitBranch
	}
	if sourceManager.CommitTag() != "" {
		commitBranch = sourceManager.CommitTag()
		gitAction = GitCommitTag
	}
	mergeRequest := sourceManager.MergeRequest()
	if mergeRequest != nil {
		gitAction = GitMergeRequest
		scanTitle = mergeRequest.MergeRequestTitle
		commitBranch = mergeRequest.SourceBranch
		targetBranch = mergeRequest.TargetBranch
		mergeRequestId = mergeRequest.MergeRequestID
	}
	repoName := sourceManager.ProjectGroup() + "/" + sourceManager.ProjectName()
	isDefault := commitBranch == sourceManager.DefaultBranch()
	body := CiScanRequest{
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
		Scanner:        scannerName,
		Type:           scannerType,
		JobUrl:         sourceManager.JobURL(),
		IsDefault:      Ptr(isDefault),
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

func (handler *RemoteHandler) CompletedScan() {
	err := handler.client.UpdateScan(handler.scanId, UpdateCIScanRequest{
		Status:      Ptr(StatusCompleted),
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
