package analyzer

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/califio/code-secure-analyzer/git"
	"github.com/califio/code-secure-analyzer/logger"
	"os"
)

type RemoteHandler struct {
	server   string
	token    string
	scanInfo *CiScanInfo
	isBlock  bool
	client   *Client
}

func NewRemoteHandler(codeSecureServer, codeSecureToken string) (*RemoteHandler, error) {
	apiClient := NewClient(codeSecureServer, codeSecureToken)
	if apiClient.TestConnection() {
		return &RemoteHandler{server: codeSecureServer, token: codeSecureToken, client: apiClient, isBlock: false}, nil
	}
	return nil, errors.New("failed to connect to remote server")
}

func (handler *RemoteHandler) HandleSCA(sourceManager git.GitEnv, result ScaResult) {
	response, err := handler.client.UploadDependency(UploadDependencyRequest{
		ScanId:              handler.scanInfo.ScanId,
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

func (handler *RemoteHandler) HandleSastFindings(input HandleSastFindingPros) {
	response, err := handler.client.UploadFinding(UploadFindingRequest{
		ScanId:       handler.scanInfo.ScanId,
		Findings:     input.Result.Findings,
		Strategy:     input.Strategy,
		ChangedFiles: input.ChangedFiles,
	})
	if err != nil {
		logger.Error(err.Error())
		return
	}
	err = SaveFindingResult(*response)
	if err != nil {
		logger.Error(err.Error())
	}
	if input.SourceManager == nil {
		logger.Warn("there is no source manager (GitLab, GitHub, vv)")
	}
	if len(response.NewFindings) > 0 {
		logger.Warn(fmt.Sprintf("There are %d new findings", len(response.NewFindings)))

		printFindings(response.NewFindings)
	}

	if len(response.FixedFindings) > 0 {
		logger.Info(fmt.Sprintf("There are %d findings that have been fixed", len(response.FixedFindings)))
		printFindings(response.FixedFindings)
	}

	if len(response.ConfirmedFindings) > 0 {
		logger.Info(fmt.Sprintf("There are still %d findings not yet fixed", len(response.ConfirmedFindings)))
		printFindings(response.ConfirmedFindings)
	}

	if len(response.OpenFindings) > 0 {
		logger.Info(fmt.Sprintf("There are %d findings need to verify", len(response.OpenFindings)))
		printFindings(response.OpenFindings)
	}

	logger.Info("View Detail: " + handler.scanInfo.ScanUrl)

	if input.SourceManager != nil {
		sourceManager := input.SourceManager
		// comment new findings on merge request
		mergeRequestId := sourceManager.MergeRequestID()
		if mergeRequestId != "" {
			if len(response.NewFindings) > 0 {
				for _, newFinding := range response.NewFindings {
					location := newFinding.Location
					if location != nil {
						locationUrl := fmt.Sprintf("%s/-/blob/%s/%s#L%d", sourceManager.ProjectURL(), sourceManager.CommitSha(), location.Path, location.StartLine)
						remoteFindingUrl := fmt.Sprintf("%s/#/finding/%s", handler.server, newFinding.ID)
						msg := fmt.Sprintf("**[%s](%s)**\n\n**Location:** `%s` @ [%s](%s)\n\n**Description**\n\n%s", newFinding.Name, remoteFindingUrl, location.Snippet, location.Path, locationUrl, newFinding.Description)
						if newFinding.Recommendation != "" {
							msg += fmt.Sprintf("\n\n**Recommendation**\n\n %s", newFinding.Recommendation)
						}
						if newFinding.Metadata != nil && len(newFinding.Metadata.FindingFlow) > 0 {
							flow := ""
							for index, step := range newFinding.Metadata.FindingFlow {
								url := fmt.Sprintf("%s/-/blob/%s/%s#L%d", sourceManager.ProjectURL(), sourceManager.CommitSha(), step.Path, step.StartLine)
								flow += fmt.Sprintf("%d. `%s` @ [%s](%s)\n", index+1, step.Snippet, step.Path, url)
							}
							codeFlow := fmt.Sprintf("\n\n<details>\n<summary>SastFinding Flow</summary>\n\n%s\n</details>", flow)
							msg += codeFlow
						}
						_ = sourceManager.CreateMRDiscussion(git.MRDiscussionOption{
							Title:     newFinding.Name,
							Body:      msg,
							Path:      location.Path,
							StartLine: location.StartLine,
							EndLine:   location.EndLine,
						})
					}

				}
			}
		}
	}
	handler.isBlock = response.IsBlock
}

func (handler *RemoteHandler) OnStart(sourceManager git.GitEnv, scannerName string, scannerType ScannerType) (*CiScanInfo, error) {
	gitAction := GitCommitBranch
	scanTitle := sourceManager.CommitTitle()
	commitBranch := sourceManager.CommitBranch()
	targetBranch := ""
	mergeRequestId := ""
	if sourceManager.CommitTag() != "" {
		commitBranch = sourceManager.CommitTag()
		gitAction = GitCommitTag
	}
	if sourceManager.MergeRequestID() != "" {
		gitAction = GitMergeRequest
		scanTitle = sourceManager.MergeRequestTitle()
		commitBranch = sourceManager.SourceBranch()
		targetBranch = sourceManager.TargetBranch()
		mergeRequestId = sourceManager.MergeRequestID()
	}
	isDefault := commitBranch == sourceManager.DefaultBranch()
	body := CiScanRequest{
		Source:         sourceManager.Provider(),
		RepoId:         sourceManager.ProjectID(),
		RepoUrl:        sourceManager.ProjectURL(),
		RepoName:       sourceManager.ProjectName(),
		GitAction:      gitAction,
		ScanTitle:      scanTitle,
		CommitBranch:   commitBranch,
		CommitHash:     sourceManager.CommitSha(),
		TargetBranch:   targetBranch,
		MergeRequestId: mergeRequestId,
		Scanner:        scannerName,
		Type:           scannerType,
		JobUrl:         sourceManager.JobURL(),
		IsDefault:      Ptr(isDefault),
	}
	scanInfo, err := handler.client.InitScan(body)
	handler.scanInfo = scanInfo
	return scanInfo, err
}

func (handler *RemoteHandler) OnCompleted() {
	err := handler.client.UpdateScan(handler.scanInfo.ScanId, UpdateCIScanRequest{
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

func (handler *RemoteHandler) OnError(err error) {
	_ = handler.client.UpdateScan(handler.scanInfo.ScanId, UpdateCIScanRequest{
		Status:      Ptr(StatusError),
		Description: Ptr(err.Error()),
	})
}

func SaveFindingResult(result UploadFindingResponse) error {
	output := "finding_results.json"
	if os.Getenv("FINDING_OUTPUT") != "" {
		output = os.Getenv("FINDING_OUTPUT")
	}
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	logger.Info("Save finding result to: " + output)
	return os.WriteFile(output, data, 0644)
}
