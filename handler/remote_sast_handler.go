package handler

import (
	"analyzer/api"
	"analyzer/finding"
	"analyzer/git"
	"analyzer/logger"
	"fmt"
)

type RemoteSASTHandler struct {
	scanId string
	client *api.Client
}

func NewRemoteSASTHandler(client *api.Client) *RemoteSASTHandler {
	return &RemoteSASTHandler{client: client}
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
			var findings []finding.SASTFinding
			findings = append(findings, response.OpenFindings...)
			findings = append(findings, response.ConfirmedFindings...)
			err := sourceManager.CommentSASTFindingOnMergeRequest(findings, mergeRequest)
			if err != nil {
				logger.Error("Comment on merge request error")
				logger.Error(err.Error())
			}
		}
	}
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
		IsDefault:      commitBranch == sourceManager.DefaultBranch(),
	}
	scanInfo, err := handler.client.InitScan(&body)
	if scanInfo != nil {
		handler.scanId = scanInfo.ScanId
	}
	if err != nil {
		logger.Error(err.Error())
	}
}
