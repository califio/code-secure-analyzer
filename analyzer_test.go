package main

import (
	"analyzer/logger"
	"analyzer/sarif"
	"analyzer/scm"
	"encoding/json"
	"github.com/xanzy/go-gitlab"
	"os"
	"testing"
)

func TestScan(t *testing.T) {
	os.Setenv("GITLAB_TOKEN", "change_me")
	os.Setenv("CI_SERVER_URL", "https://gitlab.com")
	os.Setenv("CI_MERGE_REQUEST_IID", "18")
	os.Setenv("CI_PROJECT_ID", "50471840")
	data, _ := os.ReadFile("../testdata/semgrep.sarif")
	var rep sarif.Sarif
	err := json.Unmarshal(data, &rep)
	if err != nil {
		logger.Error(err.Error())
	}
	findings := sarif.ToFindings(&rep)

	RegisterHandler(&DefaultHandler{})
	// register source manager (GitLab, GitHub)
	// gitlab
	gitlab, err := scm.NewGitlab()
	if err != nil {
		logger.Error(err.Error())
	} else {
		RegisterSourceManager(gitlab)
	}
	HandleFindings(findings)
}

func TestCommentMergeRequest(t *testing.T) {
	accessToken := "glpat-e9CcCrFjgixxN7debYhw"
	serverUrl := "https://gitlab.com"
	projectId := "50471840"
	mergeRequestID := 20
	// Initialize the GitLab client
	client, _ := gitlab.NewClient(accessToken, gitlab.WithBaseURL(serverUrl))
	mr, _, err := client.MergeRequests.GetMergeRequest(projectId, mergeRequestID, nil)
	if err != nil {
		logger.Error(err.Error())
	}
	// Create a new discussion each finding
	discussion, _, err := client.Discussions.CreateMergeRequestDiscussion(
		projectId,
		mergeRequestID,
		&gitlab.CreateMergeRequestDiscussionOptions{
			Body: gitlab.Ptr("Test Discussion"),
			Position: &gitlab.PositionOptions{
				BaseSHA:      &mr.DiffRefs.BaseSha,
				StartSHA:     &mr.DiffRefs.StartSha,
				HeadSHA:      &mr.DiffRefs.HeadSha,
				OldPath:      gitlab.Ptr("src/main/java/com/scalesec/vulnado/Cowsay.java"),
				NewPath:      gitlab.Ptr("src/main/java/com/scalesec/vulnado/Cowsay.java"),
				PositionType: gitlab.Ptr("text"),
				NewLine:      gitlab.Ptr(11),
				//OldLine: gitlab.Ptr(9),
			},
		},
	)
	if err != nil {
		logger.Error(err.Error())
	} else {
		logger.Info(discussion.ID)
	}
}
